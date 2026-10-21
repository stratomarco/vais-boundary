"""The VAIS gateway core: one mediation point that holds the tool credentials (P1b-5).

``MCPProtectedClient`` is a library the agent host calls, so the host decides which values
are trusted, which contract applies and whether the call goes through VAIS at all. Complete
mediation is then an assumption about that host (LIM-050). The gateway moves the decision
into a separate process that is the only holder of the upstream tools' credentials, so a
call that does not go through it has nothing to authenticate with.

That only helps if the gateway trusts nothing the agent sends, so this module takes three
jobs away from the caller:

- **Contracts** come from operator-owned files, looked up by the SHA-256 of the session
  token the agent presents. The agent cannot name, widen or replace its contract.
- **Labels** are assigned here. Every argument is model output, labelled
  ``derived_untrusted`` at the highest confidentiality the session has received through the
  gateway so far, except an argument exactly equal to its contract binding, which carries
  the binding's trusted label. This is ``derive_model_output``'s rule, applied at the
  boundary, and it makes LIM-053's re-labelling a library function.
- **Approvals** are granted by an operator into the shared ``ApprovalStore`` file. The gateway
  writes a pending request when an action needs one, and never grants.

This module does not import the MCP SDK. ``vais.gateway_server`` connects it to the protocol.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Mapping
import uuid


from .approvals import ApprovalStore
from .audit import AuditTrail
from .durable import SharedStateLock, write_json_atomic
from .exceptions import PolicyValidationError
from .ledger import LedgerEntry, SessionLedger
from .mcp import (
    MCPCallState,
    MCPExecutionRecord,
    MCPProfile,
    MCPReadBackReconciler,
    MCPProtectedClient,
    MCPToolBinding,
    MCPToolSession,
    MCPUnprotectedClient,
    _confidentiality,
    _effect_from_binding,
    _fail,
    _known_keys,
    _mapping,
    _string,
)
from .models import (
    AllowedValues,
    ValueBudget,
    ConfidentialityLevel,
    DecisionType,
    PlannedAction,
    Provenance,
    TaskContract,
    TrustLevel,
    TrustedValue,
    Value,
    action_fingerprint,
    deep_freeze,
    security_equal,
    session_amount,
)
from .monitor import ReferenceMonitor
from .yaml_input import read_yaml_document

# SEP-986, the MCP tool-name rule. Exposed names are checked against it at startup.
_TOOL_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def token_digest(token: str) -> str:
    """The SHA-256 a contract file stores in place of the session token itself."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- contracts ---------------------------------------------------------------------

_CONTRACT_KEYS = {
    "version", "token_sha256", "principal_id", "session_id", "tenant_id", "capability_id",
    "allowed_tools", "granted_scopes", "bound_arguments", "approved_action_fingerprints",
    "not_before", "not_after", "allowed_values", "budgets", "value_budgets",
}


def load_gateway_contract(path: str | Path) -> tuple[str, TaskContract]:
    """Load one operator-owned contract file: the token digest and the contract it grants.

    Parsed strictly, like every VAIS security file. Bound values are trusted with source
    ``contract`` and may carry a confidentiality level:
    ``bound_arguments: {tool: {argument: value}}`` or
    ``{tool: {argument: {value: ..., confidentiality: secret}}}``.

    Where one binding is not enough (DEC-067), ``allowed_values: {tool: {argument:
    {values: [...], once: true, confidentiality: ...}}}`` lists the values an argument may
    take, each at most once per session with ``once``, and ``budgets: {tool: {argument:
    4650.00}}`` caps the sum of a numeric argument over the session. ``value_budgets:
    {tool: {argument: {per: other_argument, limits: {value: 1250.00, ...}}}}`` caps it for
    each allowed value of another argument (DEC-069).
    """
    location = str(path)
    try:
        raw = read_yaml_document(path, location)
    except OSError as exc:
        raise PolicyValidationError(f"{location}: cannot read contract ({type(exc).__name__})") from None
    raw = _mapping(raw, location)
    _known_keys(raw, _CONTRACT_KEYS, location)
    if raw.get("version") != 1 or isinstance(raw.get("version"), bool):
        _fail(f"{location}.version", "must be 1")
    digest = raw.get("token_sha256")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        _fail(f"{location}.token_sha256", "must be 64 lowercase hex characters")

    def names(key: str) -> frozenset[str]:
        value = raw.get(key, [])
        if not isinstance(value, list):
            _fail(f"{location}.{key}", "must be a list")
        return frozenset(_string(item, f"{location}.{key}[]") for item in value)

    bindings: dict[tuple[str, str], TrustedValue] = {}
    for tool, arguments in _mapping(raw.get("bound_arguments", {}), f"{location}.bound_arguments").items():
        tool_path = f"{location}.bound_arguments.{tool}"
        tool = _string(tool, tool_path)
        for argument, spec in _mapping(arguments, tool_path).items():
            argument_path = f"{tool_path}.{argument}"
            argument = _string(argument, argument_path)
            level = ConfidentialityLevel.PUBLIC
            if isinstance(spec, dict):
                _known_keys(spec, {"value", "confidentiality"}, argument_path)
                if "value" not in spec:
                    _fail(argument_path, "a mapping binding needs 'value'")
                if "confidentiality" in spec:
                    level = _confidentiality(spec["confidentiality"], f"{argument_path}.confidentiality")
                spec = spec["value"]
            bindings[(tool, argument)] = TrustedValue(spec, source="contract", confidentiality=level)

    choices: dict[tuple[str, str], AllowedValues] = {}
    for tool, arguments in _mapping(raw.get("allowed_values", {}), f"{location}.allowed_values").items():
        tool_path = f"{location}.allowed_values.{tool}"
        tool = _string(tool, tool_path)
        for argument, spec in _mapping(arguments, tool_path).items():
            argument_path = f"{tool_path}.{argument}"
            argument = _string(argument, argument_path)
            spec = _mapping(spec, argument_path)
            _known_keys(spec, {"values", "once", "confidentiality"}, argument_path)
            values = spec.get("values")
            if not isinstance(values, list) or not values:
                _fail(f"{argument_path}.values", "must be a non-empty list")
            once = spec.get("once", False)
            if not isinstance(once, bool):
                _fail(f"{argument_path}.once", "must be true or false")
            level = ConfidentialityLevel.PUBLIC
            if "confidentiality" in spec:
                level = _confidentiality(spec["confidentiality"], f"{argument_path}.confidentiality")
            try:
                choices[(tool, argument)] = AllowedValues(
                    tuple(TrustedValue(value, source="contract", confidentiality=level) for value in values), once=once)
            except ValueError as exc:
                _fail(argument_path, str(exc))

    budgets: dict[tuple[str, str], Any] = {}
    for tool, arguments in _mapping(raw.get("budgets", {}), f"{location}.budgets").items():
        tool_path = f"{location}.budgets.{tool}"
        tool = _string(tool, tool_path)
        for argument, limit in _mapping(arguments, tool_path).items():
            argument_path = f"{tool_path}.{argument}"
            if session_amount(limit) is None:
                _fail(argument_path, "must be a finite, non-negative amount")
            budgets[(tool, _string(argument, argument_path))] = limit

    value_budgets: dict[tuple[str, str], ValueBudget] = {}
    for tool, arguments in _mapping(raw.get("value_budgets", {}), f"{location}.value_budgets").items():
        tool_path = f"{location}.value_budgets.{tool}"
        tool = _string(tool, tool_path)
        for argument, spec in _mapping(arguments, tool_path).items():
            argument_path = f"{tool_path}.{argument}"
            argument = _string(argument, argument_path)
            spec = _mapping(spec, argument_path)
            _known_keys(spec, {"per", "limits"}, argument_path)
            try:
                value_budgets[(tool, argument)] = ValueBudget(
                    per=_string(spec.get("per"), f"{argument_path}.per"),
                    limits=_mapping(spec.get("limits"), f"{argument_path}.limits"))
            except ValueError as exc:
                if isinstance(exc, PolicyValidationError):
                    raise
                _fail(argument_path, str(exc))

    window: dict[str, float] = {}
    for key in ("not_before", "not_after"):
        if key in raw:
            value = raw[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                _fail(f"{location}.{key}", "must be seconds since the epoch")
            window[key] = float(value)

    try:
        contract = TaskContract(
            allowed_tools=names("allowed_tools"),
            granted_scopes=names("granted_scopes"),
            bound_arguments=bindings,
            approved_action_fingerprints=names("approved_action_fingerprints"),
            principal_id=_string(raw.get("principal_id"), f"{location}.principal_id"),
            session_id=_string(raw.get("session_id"), f"{location}.session_id"),
            tenant_id=_string(raw.get("tenant_id"), f"{location}.tenant_id"),
            capability_id=_string(raw.get("capability_id"), f"{location}.capability_id"),
            allowed_values=choices,
            budgets=budgets,
            value_budgets=value_budgets,
            **window,
        )
    except ValueError as exc:
        if isinstance(exc, PolicyValidationError):
            raise
        raise PolicyValidationError(f"{location}: {exc}") from None
    return digest, contract


class ContractRegistry:
    """Contracts in an operator-owned directory, looked up by session token.

    The directory is read on every lookup, so adding a file grants a session and deleting
    it revokes the session at its next call. A file that fails to parse grants nothing and
    is reported in ``problems``; two files with the same token digest both grant nothing,
    since the gateway cannot tell which the operator meant.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def scan(self) -> tuple[dict[str, TaskContract], tuple[str, ...]]:
        contracts, _, problems = self._scan()
        return contracts, problems

    def _scan(self) -> tuple[dict[str, TaskContract], dict[str, str], tuple[str, ...]]:
        contracts: dict[str, TaskContract] = {}
        files: dict[str, str] = {}
        duplicates: set[str] = set()
        problems: list[str] = []
        for path in sorted(self.directory.glob("*.yaml")):
            try:
                digest, contract = load_gateway_contract(path)
                content = hashlib.sha256(path.read_bytes()).hexdigest()
            except PolicyValidationError as exc:
                problems.append(str(exc))
                continue
            except OSError:
                problems.append(f"{path}: cannot read contract")
                continue
            if digest in contracts:
                duplicates.add(digest)
            contracts[digest] = contract
            files[digest] = content
        for digest in duplicates:
            contracts.pop(digest)
            files.pop(digest)
            problems.append(f"token digest {digest[:12]}... appears in more than one contract; none apply")
        return contracts, files, tuple(problems)

    def lookup(self, token: str) -> TaskContract | None:
        found = self.lookup_with_digest(token)
        return found[0] if found is not None else None

    def lookup_with_digest(self, token: str) -> tuple[TaskContract, str] | None:
        """The contract for ``token`` and the SHA-256 of the file that granted it, for the audit."""
        if not isinstance(token, str) or not token:
            return None
        contracts, files, _ = self._scan()
        digest = token_digest(token)
        return (contracts[digest], files[digest]) if digest in contracts else None

    def find_identity(self, principal_id: str, session_id: str, tenant_id: str,
                      capability_id: str) -> TaskContract | None:
        contracts, _ = self.scan()
        identity = (principal_id, session_id, tenant_id, capability_id)
        return next((c for c in contracts.values()
                     if (c.principal_id, c.session_id, c.tenant_id, c.capability_id) == identity), None)


# --- labelling ---------------------------------------------------------------------

@dataclass(frozen=True)
class MintedValue:
    """A value a declared mint made authority for one argument in one session (DEC-064)."""

    value: str | int
    confidentiality: ConfidentialityLevel
    source_tool: str


def label_agent_action(
    tool: str,
    arguments: Mapping[str, Any],
    contract: TaskContract,
    context_level: ConfidentialityLevel,
    context_trust: TrustLevel = TrustLevel.DERIVED_UNTRUSTED,
    minted: Mapping[str, tuple[MintedValue, ...]] | None = None,
) -> PlannedAction:
    """Build the ``PlannedAction`` for arguments that arrived from the agent.

    Nothing the agent sends is trusted on its say-so. An argument exactly equal to its
    contract binding takes the binding's label, since its value is the one the operator
    wrote, and so does one exactly equal to one of its contract's allowed values (DEC-067).
    An argument exactly equal to a value minted for it this session (``minted``,
    argument name to values) is trusted with the minting tool as its source, since the
    operator declared that tool's result to be authority for it. Every other argument is
    model output at the session's confidentiality level.

    The action's origin (P1b-6) is the session's context as the gateway has seen it:
    trusted until the session receives its first tool result, which VAIS always treats
    as untrusted, and untrusted from then on. The gateway cannot see the agent's prompt,
    so that is assumed to be the trusted task (LIM-061).
    """
    values: dict[str, Value] = {}
    for name, data in arguments.items():
        bound = contract.bound_arguments.get((tool, name))
        frozen = deep_freeze(data)
        match = next((m for m in (minted or {}).get(name, ()) if security_equal(frozen, m.value)), None)
        allowed = contract.allowed_values.get((tool, name))
        choice = None if allowed is None else allowed.match(frozen)
        if bound is not None and security_equal(frozen, bound.data):
            values[name] = Value(data, bound.provenance)
        elif choice is not None:
            values[name] = Value(data, choice.provenance)
        elif match is not None:
            values[name] = Value(data, Provenance(
                source=f"gateway:minted:{match.source_tool}", trust=TrustLevel.TRUSTED,
                confidentiality=match.confidentiality,
            ))
        else:
            values[name] = Value(data, Provenance(
                source="model_output", trust=TrustLevel.DERIVED_UNTRUSTED, confidentiality=context_level,
            ))
    origin = Provenance(source="gateway:session_context", trust=context_trust, confidentiality=context_level)
    return PlannedAction(tool, values, origin=origin)


# --- outcomes ------------------------------------------------------------------------

class GatewayOutcomeKind(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    INDETERMINATE = "indeterminate"
    UNAUTHENTICATED = "unauthenticated"


@dataclass(frozen=True)
class GatewayOutcome:
    kind: GatewayOutcomeKind
    message: str
    result: Any = None
    approval_request: str | None = None
    reasons: tuple[str, ...] = ()

    @property
    def is_error(self) -> bool:
        return self.kind is not GatewayOutcomeKind.ALLOWED


class _SessionContext:
    """What a session has received through the gateway: its confidentiality high-water mark,
    whether any tool result has reached the agent yet, and the values declared mints made
    authority (DEC-064).

    All three only ever grow. Without a path they live in memory and a restart starts the
    session fresh, so an agent that read secret data could send it once the gateway restarts
    (LIM-063). With a path they are a file every call reloads under an operating-system
    lock, so a restarted gateway, or a second one sharing the state directory, labels the
    session's next arguments as the first would have.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.level = ConfidentialityLevel.PUBLIC
        self.trust = TrustLevel.TRUSTED
        self.minted: dict[tuple[str, str], tuple[MintedValue, ...]] = {}
        self.lock = SharedStateLock(path, self._reload)
        if path is not None:
            with self.lock:
                pass

    def current(self) -> tuple[ConfidentialityLevel, TrustLevel]:
        with self.lock:
            return self.level, self.trust

    def minted_for(self, tool: str) -> dict[str, tuple[MintedValue, ...]]:
        with self.lock:
            return {argument: values for (target, argument), values in self.minted.items() if target == tool}

    def observe(self, level: ConfidentialityLevel) -> None:
        """Record that a result at ``level`` reached the agent."""
        with self.lock:
            new_level = level if level.rank > self.level.rank else self.level
            # MCP results are never authority (label_mcp_input), so once one is in the
            # agent's context, whatever it plans next has an untrusted origin.
            new_trust = TrustLevel.DERIVED_UNTRUSTED
            if (new_level, new_trust) == (self.level, self.trust):
                return
            self._write(new_level, new_trust, self.minted)
            self.level, self.trust = new_level, new_trust

    def mint(self, targets: tuple[tuple[str, str], ...], value: MintedValue) -> None:
        """Make ``value`` authority for each target argument for the rest of the session."""
        with self.lock:
            minted = dict(self.minted)
            for target in targets:
                if value not in minted.get(target, ()):
                    minted[target] = (*minted.get(target, ()), value)
            if minted == self.minted:
                return
            self._write(self.level, self.trust, minted)
            self.minted = minted

    def _write(self, level: ConfidentialityLevel, trust: TrustLevel,
               minted: dict[tuple[str, str], tuple[MintedValue, ...]]) -> None:
        if self.path is None:
            return
        write_json_atomic(self.path, {
            "version": 1, "confidentiality": level.value, "trust": trust.value,
            "minted": [[tool, argument, m.value, m.confidentiality.value, m.source_tool]
                       for (tool, argument), values in sorted(minted.items()) for m in values],
        })

    def _reload(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if (not isinstance(raw, dict) or raw.get("version") != 1
                or set(raw) != {"version", "confidentiality", "trust", "minted"} or not isinstance(raw["minted"], list)):
            raise ValueError(f"{self.path}: not a version 1 gateway session context")
        minted: dict[tuple[str, str], tuple[MintedValue, ...]] = {}
        for item in raw["minted"]:
            if (not isinstance(item, list) or len(item) != 5 or not isinstance(item[0], str)
                    or not isinstance(item[1], str) or isinstance(item[2], bool)
                    or not isinstance(item[2], (str, int)) or not isinstance(item[4], str)):
                raise ValueError(f"{self.path}: malformed minted value")
            key = (item[0], item[1])
            minted[key] = (*minted.get(key, ()), MintedValue(item[2], ConfidentialityLevel(item[3]), item[4]))
        self.level = ConfidentialityLevel(raw["confidentiality"])
        self.trust = TrustLevel(raw["trust"])
        self.minted = minted


@dataclass
class _SessionState:
    ledger: SessionLedger
    context: _SessionContext = field(default_factory=_SessionContext)

    @property
    def context_level(self) -> ConfidentialityLevel:
        return self.context.current()[0]

    @property
    def context_trust(self) -> TrustLevel:
        return self.context.current()[1]


class _RetryLedger:
    """A session ledger seen as if one earlier call had not been made: for deciding a retry of it.

    A consequential call whose outcome is unknown was counted when it was allowed. Its exact
    retry, sent with the same idempotency key or after an operator said it did not happen, is
    the same call, so it is decided against the ledger without that entry and records nothing
    new: limits, single-use values and budgets count it once (DEC-074).
    """

    def __init__(self, base: SessionLedger, fingerprint: str) -> None:
        self.base = base
        self.identity = base.identity
        self.lock = base.lock
        self.fingerprint = fingerprint

    @property
    def _entries(self) -> list[LedgerEntry]:
        with self.base.lock:
            entries = list(self.base._entries)
        for index in range(len(entries) - 1, -1, -1):
            if entries[index].action_fingerprint == self.fingerprint:
                del entries[index]
                break
        return entries

    matches = SessionLedger.matches
    entries = SessionLedger.entries
    calls = SessionLedger.calls
    contract_approval_used = SessionLedger.contract_approval_used
    used_values = SessionLedger.used_values
    total = SessionLedger.total
    total_for = SessionLedger.total_for

    def record(self, entry: LedgerEntry) -> None:
        """Nothing: the original entry already stands for this call."""


INDETERMINATE_DIR = "indeterminate"
_INDETERMINATE_KEYS = {"version", "call_id", "tool", "arguments", "action_fingerprint", "idempotency_key",
                       "principal_id", "session_id", "tenant_id", "capability_id", "status"}
_RESOLUTION_KEYS = {"version", "call_id", "outcome", "by", "at"}
RESOLUTION_OUTCOMES = ("happened", "did_not_happen")


@dataclass(frozen=True)
class IndeterminateCall:
    """A consequential call whose outcome is unknown, kept until it is reconciled (DEC-074).

    The gateway writes one file per call in ``<pending>/indeterminate/``, beside approval
    requests, for operators to see. ``status`` is ``unresolved``, or ``did_not_happen`` once an
    operator has said so: then it no longer holds the tool, and its exact retry is decided as
    the same call.
    """

    path: Path
    call_id: str
    tool: str
    arguments: dict[str, Any]
    action_fingerprint: str
    idempotency_key: str | None
    identity: tuple[str, str, str, str]
    status: str

    @classmethod
    def load(cls, path: Path) -> "IndeterminateCall":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != 1 or set(raw) != _INDETERMINATE_KEYS:
            raise ValueError(f"{path}: not a version 1 indeterminate call record")
        if raw["status"] not in ("unresolved", "did_not_happen") or not isinstance(raw["arguments"], dict):
            raise ValueError(f"{path}: malformed indeterminate call record")
        identity = tuple(raw[key] for key in ("principal_id", "session_id", "tenant_id", "capability_id"))
        return cls(path, raw["call_id"], raw["tool"], raw["arguments"], raw["action_fingerprint"],
                   raw["idempotency_key"], identity, raw["status"])  # type: ignore[arg-type]

    def body(self, status: str | None = None) -> dict[str, Any]:
        principal, session, tenant, capability = self.identity
        return {"version": 1, "call_id": self.call_id, "tool": self.tool, "arguments": _plain(self.arguments),
                "action_fingerprint": self.action_fingerprint, "idempotency_key": self.idempotency_key,
                "principal_id": principal, "session_id": session, "tenant_id": tenant,
                "capability_id": capability, "status": status or self.status}

    def resolution_path(self) -> Path:
        return self.path.with_name(f"{self.call_id}.resolution.json")


@dataclass(frozen=True)
class ExposedTool:
    name: str
    binding: MCPToolBinding


def exposed_name(binding: MCPToolBinding) -> str:
    return f"{binding.server_id}.{binding.tool_name}"


# --- the gateway ---------------------------------------------------------------------

# Observe-only mode cannot be configured to last longer than this (1.0 track, step 5).
OBSERVE_MAX_SECONDS = 14 * 24 * 3600


class Gateway:
    """Decide and forward calls for agents that hold a session token and nothing else.

    ``sessions`` maps each upstream ``server_id`` to a live MCP client session that the
    gateway opened with the upstream's credentials. ``reason_disclosure`` controls what a
    refused agent is told: ``"decision"`` (the default) gives the outcome only, so denials
    are not a probing oracle (S13, IMP-003); ``"reasons"`` adds the monitor's reason codes.
    The audit trail always keeps them.

    ``state_dir`` keeps each session's ledger and context in files there, so call limits,
    single-use contract approvals and the confidentiality high-water mark survive a restart
    and hold across gateways on one machine sharing the directory. Without it they live in
    this process's memory (LIM-063).

    ``observe_until`` (seconds since the epoch) runs the gateway in observe-only mode until
    that moment: every call is decided as if enforcing and the decision is audited as
    ``would_<decision>``, but the call is forwarded whatever the decision. It must be at most
    ``OBSERVE_MAX_SECONDS`` ahead, so the mode cannot be left on by accident; when it passes,
    the gateway enforces without a restart. Unauthenticated calls, tools the contract does
    not allow and malformed arguments are refused in either mode.
    """

    def __init__(
        self,
        *,
        profile: MCPProfile,
        monitor: ReferenceMonitor,
        registry: ContractRegistry,
        sessions: Mapping[str, MCPToolSession],
        approval_store: ApprovalStore,
        pending_dir: str | Path,
        audit: AuditTrail | None = None,
        audit_path: str | Path | None = None,
        reason_disclosure: str = "decision",
        state_dir: str | Path | None = None,
        call_timeout: float | None = None,
        observe_until: float | None = None,
        clock: Callable[[], float] | None = None,
        configuration: Mapping[str, str] | None = None,
    ) -> None:
        self._clock = clock or time.time
        if observe_until is not None:
            if isinstance(observe_until, bool) or not isinstance(observe_until, (int, float)):
                raise PolicyValidationError("observe_until must be a time in seconds since the epoch")
            if observe_until - self._clock() > OBSERVE_MAX_SECONDS:
                raise PolicyValidationError("observe_until must be at most 14 days ahead; observe-only "
                                            "mode forwards calls VAIS would refuse")
        self.observe_until = float(observe_until) if observe_until is not None else None
        if reason_disclosure not in ("decision", "reasons"):
            raise ValueError("reason_disclosure must be 'decision' or 'reasons'")
        self.profile = profile
        self.monitor = monitor
        self.registry = registry
        self.sessions = dict(sessions)
        self.approval_store = approval_store
        self.pending_dir = Path(pending_dir)
        self.audit = audit or AuditTrail()
        self.audit_path = Path(audit_path) if audit_path is not None else None
        self.reason_disclosure = reason_disclosure
        self.state_dir = Path(state_dir) if state_dir is not None else None
        self.call_timeout = call_timeout
        self._states: dict[tuple[str, str, str], _SessionState] = {}
        self._lock = threading.RLock()
        self._flushed = 0

        tools: dict[str, ExposedTool] = {}
        for binding in profile.bindings:
            name = exposed_name(binding)
            if not _TOOL_NAME.fullmatch(name):
                raise PolicyValidationError(f"exposed tool name {name!r} does not satisfy the MCP tool-name rule")
            if name in tools:
                raise PolicyValidationError(f"exposed tool name {name!r} is not unique")
            if binding.server_id not in self.sessions:
                raise PolicyValidationError(f"no upstream session for server {binding.server_id!r}")
            confirm = binding.effect.confirm
            if confirm is not None and confirm.server_id not in self.sessions:
                raise PolicyValidationError(
                    f"{name!r} reads its effect back from server {confirm.server_id!r}, which has no upstream session")
            tools[name] = ExposedTool(name, binding)
        self._tools = tools
        # Declared stores must not carry data or authority from one session into another (DEC-070).
        from .stores import store_flow_problems
        problems = store_flow_problems(profile, monitor.policy)
        if problems:
            raise PolicyValidationError("unsafe store flows: " + "; ".join(problems))
        if configuration is not None:
            # What this gateway runs with, by digest, so each later event can be tied to the
            # exact policy, profile and configuration that produced it (R8, DEC-074).
            self.audit.record("gateway_configuration", details=dict(configuration))
        if self.observe_until is not None:
            self.audit.record("observe_only_configured", details={
                "observe_until": _iso(self.observe_until), "active": self.observing()})

    def observing(self) -> bool:
        """True while observe-only mode is configured and has not expired."""
        return self.observe_until is not None and self._clock() < self.observe_until

    # The agent sees only the tools its contract allows. This narrows what the model is
    # offered; it is not the authorization, which the monitor makes on every call.
    def tools_for(self, token: str) -> tuple[ExposedTool, ...]:
        contract = self.registry.lookup(token)
        if contract is None:
            return ()
        return tuple(tool for tool in self._tools.values() if tool.binding.canonical_tool in contract.allowed_tools)

    def _state(self, contract: TaskContract) -> _SessionState:
        key = (contract.principal_id, contract.session_id, contract.tenant_id)
        with self._lock:
            state = self._states.get(key)
            if state is None:
                if self.state_dir is None:
                    state = _SessionState(SessionLedger(contract))
                else:
                    # File names from a digest of the identity, so an identity cannot
                    # name a path.
                    stem = hashlib.sha256(json.dumps(list(key)).encode("utf-8")).hexdigest()[:32]
                    state = _SessionState(SessionLedger(contract, self.state_dir / f"{stem}.ledger.json"),
                                          _SessionContext(self.state_dir / f"{stem}.context.json"))
                self._states[key] = state
            return state

    async def call(self, token: str, name: str, arguments: Mapping[str, Any] | None) -> GatewayOutcome:
        try:
            return await self._call(token, name, dict(arguments or {}))
        finally:
            self._flush_audit()

    async def _call(self, token: str, name: str, arguments: dict[str, Any]) -> GatewayOutcome:
        # One id for every event this call produces, so a reviewer can follow it from
        # decision to dispatch, effect, receipt and reconciliation (R8, DEC-074).
        call_id = uuid.uuid4().hex
        found = self.registry.lookup_with_digest(token)
        if found is None:
            # Nothing about the token is recorded; its digest would help an attacker more
            # than the operator.
            self.audit.record("gateway_unauthenticated", tool=name if isinstance(name, str) else None,
                              details={"call_id": call_id})
            return GatewayOutcome(GatewayOutcomeKind.UNAUTHENTICATED, "unauthenticated")
        contract, contract_sha256 = found
        identity = {"principal_id": contract.principal_id, "session_id": contract.session_id,
                    "tenant_id": contract.tenant_id, "capability_id": contract.capability_id}
        self.audit.record("gateway_call", tool=name if isinstance(name, str) else None,
                          details={"call_id": call_id, "contract_sha256": contract_sha256, **identity})

        exposed = self._tools.get(name)
        if exposed is None or exposed.binding.canonical_tool not in contract.allowed_tools:
            self.audit.record("gateway_unknown_tool", tool=name if isinstance(name, str) else None,
                              decision=DecisionType.DENY.value, reasons=("tool_not_exposed",),
                              details={"call_id": call_id, **identity})
            return self._refusal(GatewayOutcomeKind.DENIED, ("tool_not_exposed",))

        binding = exposed.binding
        state = self._state(contract)
        level, trust = state.context.current()
        try:
            action = label_agent_action(binding.canonical_tool, arguments, contract, level, trust,
                                        state.context.minted_for(binding.canonical_tool))
        except ValueError:
            self.audit.record("gateway_malformed_arguments", tool=binding.canonical_tool,
                              decision=DecisionType.DENY.value, reasons=("malformed_arguments",),
                              details={"call_id": call_id})
            return self._refusal(GatewayOutcomeKind.DENIED, ("malformed_arguments",))

        if self.observing():
            return await self._observe(binding, action, contract, state, call_id)

        retry_of: IndeterminateCall | None = None
        ledger: Any = state.ledger
        if binding.consequential:
            held, retry_of = await self._hold(binding, action, contract, call_id)
            if held is not None:
                return held
            if retry_of is not None:
                ledger = _RetryLedger(state.ledger, retry_of.action_fingerprint)

        client = MCPProtectedClient(
            server_id=binding.server_id,
            session=self.sessions[binding.server_id],
            profile=self.profile,
            monitor=self.monitor,
            approval_store=self.approval_store,
            audit=self.audit,
            ledger=ledger,
            reconcilers=self._reconcilers(binding),
            call_timeout=self.call_timeout,
        )
        record = await client.execute(action, contract, call_id=call_id)

        if record.call_state is not MCPCallState.NOT_CALLED and retry_of is not None:
            # The retry went out, so the earlier attempt is settled by it: either this reply
            # or a new record of this call's own unknown outcome takes its place.
            self._settle(retry_of, "superseded_by_retry", "retry", call_id)
        if record.call_state is MCPCallState.OBSERVED:
            state.context.observe(binding.result_policy.confidentiality)
            self._mint(binding, record.result.data if record.result else None, state, contract, call_id)
            return GatewayOutcome(GatewayOutcomeKind.ALLOWED, "ok", result=record.result.data if record.result else None)
        if record.call_state is MCPCallState.INDETERMINATE:
            if binding.consequential:
                self._record_indeterminate(record, contract)
            return GatewayOutcome(GatewayOutcomeKind.INDETERMINATE,
                                  "the call was dispatched and failed; its effect is unknown")
        if record.decision.type is DecisionType.REQUIRE_APPROVAL:
            request = self._request_approval(action, contract)
            return self._refusal(GatewayOutcomeKind.APPROVAL_REQUIRED, record.decision.reasons, request)
        return self._refusal(GatewayOutcomeKind.DENIED, record.decision.reasons)

    async def _observe(self, binding: MCPToolBinding, action: PlannedAction, contract: TaskContract,
                       state: _SessionState, call_id: str | None = None) -> GatewayOutcome:
        """Observe-only: audit what enforcement would decide, then forward the call anyway.

        The decision is made against the session ledger with no approval store, so the ledger
        records only the calls enforcement would have allowed (budgets and single use then
        behave as they would) and observing never consumes an operator's grant.
        """
        decision = self.monitor.evaluate(action, contract, ledger=state.ledger)
        identity = {"principal_id": contract.principal_id, "session_id": contract.session_id,
                    "tenant_id": contract.tenant_id, "capability_id": contract.capability_id, "call_id": call_id}
        self.audit.record("observe_only_decision", tool=action.tool, decision=f"would_{decision.type.value}",
                          reasons=decision.reasons, details={**identity, "observe_until": _iso(self.observe_until)})
        call = MCPUnprotectedClient(server_id=binding.server_id, session=self.sessions[binding.server_id],
                                    profile=self.profile).execute(action)
        try:
            record = await (asyncio.wait_for(call, self.call_timeout) if self.call_timeout else call)
        except asyncio.TimeoutError:
            record = None
        state_name = record.call_state.value if record is not None else MCPCallState.INDETERMINATE.value
        self.audit.record("observe_only_dispatch", tool=action.tool, details={**identity, "call_state": state_name})
        if record is not None and record.call_state is MCPCallState.OBSERVED:
            state.context.observe(binding.result_policy.confidentiality)
            self._mint(binding, record.result.data if record.result else None, state, contract, call_id)
            return GatewayOutcome(GatewayOutcomeKind.ALLOWED, "ok", result=record.result.data if record.result else None)
        if record is None or record.call_state is MCPCallState.INDETERMINATE:
            return GatewayOutcome(GatewayOutcomeKind.INDETERMINATE,
                                  "the call was dispatched and failed; its effect is unknown")
        return self._refusal(GatewayOutcomeKind.DENIED, record.decision.reasons)

    def _mint(self, binding: MCPToolBinding, result: Any, state: _SessionState, contract: TaskContract,
              call_id: str | None = None) -> None:
        """Make each declared mint's value authority for its targets in this session (DEC-064).

        Only an observed call mints, so the monitor allowed the minting call itself. The audit
        records a digest of the value, not the value.
        """
        identity = {"principal_id": contract.principal_id, "session_id": contract.session_id,
                    "tenant_id": contract.tenant_id, "capability_id": contract.capability_id}
        if call_id is not None:
            identity["call_id"] = call_id
        for spec in binding.mints:
            value = spec.value(result)
            source = "result" if spec.field is None else f"result.{spec.field}"
            # Only for tools this session's contract allows: authority it could never use is
            # not created, as the library binds a minted value only for allowed tools.
            targets = tuple(target for target in spec.targets if target[0] in contract.allowed_tools)
            if value is None or not targets:
                self.audit.record("authority_not_minted", tool=binding.canonical_tool, details={
                    "from": source, "reason": "no_value" if value is None else "no_allowed_target", **identity})
                continue
            state.context.mint(targets, MintedValue(value, binding.result_policy.confidentiality,
                                                    binding.canonical_tool))
            self.audit.record("authority_minted", tool=binding.canonical_tool, details={
                "from": source, "targets": [f"{tool}.{argument}" for tool, argument in targets],
                "value_sha256": hashlib.sha256(json.dumps(value).encode("utf-8")).hexdigest(), **identity,
            })

    # --- consequential calls with unknown outcomes (R5, DEC-074) -------------------------

    @property
    def indeterminate_dir(self) -> Path:
        return self.pending_dir / INDETERMINATE_DIR

    def _record_indeterminate(self, record: MCPExecutionRecord, contract: TaskContract) -> None:
        """Keep a consequential call whose outcome is unknown, so the tool is held until it is reconciled."""
        if record.request_id is None or record.call_id is None:
            return
        entry = IndeterminateCall(
            self.indeterminate_dir / f"{record.call_id}.json", record.call_id, record.action.tool,
            dict(record.action.plain_arguments()), record.request_id, record.idempotency_key,
            (contract.principal_id, contract.session_id, contract.tenant_id, contract.capability_id), "unresolved")
        self.indeterminate_dir.mkdir(parents=True, exist_ok=True)
        write_json_atomic(entry.path, entry.body())
        self.audit.record("indeterminate_recorded", tool=entry.tool, details={
            "call_id": entry.call_id, "action_fingerprint": entry.action_fingerprint,
            "retry_safe": record.retry_safe, **_identity_details(entry.identity)})

    def _entries(self, binding: MCPToolBinding, contract: TaskContract) -> list[IndeterminateCall]:
        """This session's unknown-outcome calls to this tool. One session: principal, session, tenant."""
        if not self.indeterminate_dir.is_dir():
            return []
        session = (contract.principal_id, contract.session_id, contract.tenant_id)
        entries = []
        for path in sorted(self.indeterminate_dir.glob("*.json")):
            if path.name.endswith(".resolution.json"):
                continue
            try:
                entry = IndeterminateCall.load(path)
            except (OSError, ValueError, KeyError):
                # A record that cannot be read holds every consequential call in every
                # session, rather than letting a retry through on a guess.
                self.audit.record("indeterminate_record_unreadable", details={"file": path.name})
                raise _Unreadable() from None
            if entry.identity[:3] == session and entry.tool == binding.canonical_tool:
                entries.append(entry)
        return entries

    async def _hold(self, binding: MCPToolBinding, action: PlannedAction, contract: TaskContract,
                    call_id: str) -> tuple[GatewayOutcome | None, IndeterminateCall | None]:
        """Refuse a consequential call while an earlier one to the same tool has an unknown outcome.

        The exact retry of a held call, when the tool takes an idempotency key, goes to the
        backend as the same call: it makes the change once, or replays its first reply, so the
        agent gets the result either way. Every other earlier call is first reconciled if it can
        be: by an operator's resolution, or by the binding's read-back confirming it happened.
        What remains holds the tool, except the exact retry of a call an operator said did not
        happen. Returns the refusal, or the earlier call this one retries.
        """
        try:
            fingerprint = action_fingerprint(action)
        except ValueError:
            fingerprint = None
        try:
            entries = self._entries(binding, contract)
            retry_of = next((entry for entry in entries if entry.action_fingerprint == fingerprint
                             and binding.idempotency_argument is not None), None)
            remaining = [entry for entry in [await self._reconcile(binding, e, call_id) for e in entries
                                             if e is not retry_of] if entry is not None]
        except _Unreadable:
            return self._held(action, contract, call_id, ("indeterminate_record_unreadable",), []), None
        if retry_of is None:
            retry_of = next((entry for entry in remaining if entry.action_fingerprint == fingerprint
                             and entry.status == "did_not_happen"), None)
        holding = [entry for entry in remaining if entry.status == "unresolved" and entry is not retry_of]
        if holding:
            return self._held(action, contract, call_id, ("indeterminate_unresolved",), holding), None
        return None, retry_of

    def _held(self, action: PlannedAction, contract: TaskContract, call_id: str, reasons: tuple[str, ...],
              holding: list[IndeterminateCall]) -> GatewayOutcome:
        identity = (contract.principal_id, contract.session_id, contract.tenant_id, contract.capability_id)
        self.audit.record("call_held", tool=action.tool, decision=DecisionType.DENY.value, reasons=reasons,
                          details={"call_id": call_id, "held_by": [entry.call_id for entry in holding],
                                   **_identity_details(identity)})
        outcome = self._refusal(GatewayOutcomeKind.DENIED, reasons)
        return GatewayOutcome(outcome.kind, outcome.message + "; an earlier call to this tool has an unknown "
                              "outcome and must be reconciled first", reasons=outcome.reasons)

    async def _reconcile(self, binding: MCPToolBinding, entry: IndeterminateCall,
                         call_id: str) -> IndeterminateCall | None:
        """Settle ``entry`` if an operator or the system of record can say what happened.

        Returns None once it is settled, else the entry as it now stands.
        """
        resolution = entry.resolution_path()
        if resolution.exists():
            try:
                raw = json.loads(resolution.read_text(encoding="utf-8"))
                valid = (isinstance(raw, dict) and raw.get("version") == 1 and set(raw) == _RESOLUTION_KEYS
                         and raw["call_id"] == entry.call_id and raw["outcome"] in RESOLUTION_OUTCOMES)
            except (OSError, ValueError):
                valid = False
            if not valid:
                self.audit.record("indeterminate_resolution_unreadable", tool=entry.tool,
                                  details={"call_id": entry.call_id})
                return entry
            if raw["outcome"] == "happened":
                self._settle(entry, "happened", "operator", call_id, by=raw["by"])
                return None
            # Kept, no longer holding, so its exact retry is decided as the same call.
            released = replace(entry, status="did_not_happen")
            write_json_atomic(entry.path, released.body())
            resolution.unlink()
            self.audit.record("indeterminate_resolved", tool=entry.tool, details={
                "call_id": entry.call_id, "outcome": "did_not_happen", "method": "operator",
                "by": raw["by"], "resolved_during": call_id, **_identity_details(entry.identity)})
            return released
        spec = binding.effect.confirm
        if entry.status != "unresolved" or spec is None:
            return entry
        sent = dict(entry.arguments)
        if binding.idempotency_argument is not None and entry.idempotency_key is not None:
            sent[binding.idempotency_argument] = entry.idempotency_key
        action = PlannedAction(entry.tool, {name: TrustedValue(value, source="gateway:indeterminate_record")
                                            for name, value in entry.arguments.items()})
        reconciler = MCPReadBackReconciler(self.sessions[spec.server_id], spec.tool_name,
                                           arguments=spec.arguments, expect=spec.expect)
        try:
            read = reconciler.reconcile(_effect_from_binding(action, binding, sent), None)
            outcome = await (asyncio.wait_for(read, self.call_timeout) if self.call_timeout else read)
        except Exception as exc:
            self.audit.record("reconciliation_failed", tool=entry.tool,
                              details={"call_id": entry.call_id, "error": type(exc).__name__})
            return entry
        # Only "it happened" is settled from a read-back. Not finding the record is not proof
        # that nothing happened; that takes an operator.
        if outcome.confidence.value == "confirmed":
            self._settle(entry, "happened", "read_back", call_id)
            return None
        self.audit.record("reconciliation_inconclusive", tool=entry.tool, details={
            "call_id": entry.call_id, "confidence": outcome.confidence.value,
            "contradicted_fields": list(outcome.contradicted_fields)})
        return entry

    def _settle(self, entry: IndeterminateCall, outcome: str, method: str, call_id: str, *,
                by: str | None = None) -> None:
        details = {"call_id": entry.call_id, "outcome": outcome, "method": method, "resolved_during": call_id,
                   **_identity_details(entry.identity)}
        if by is not None:
            details["by"] = by
        for path in (entry.resolution_path(), entry.path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        self.audit.record("indeterminate_resolved", tool=entry.tool, details=details)

    def _reconcilers(self, binding: MCPToolBinding) -> dict[str, MCPReadBackReconciler]:
        """The read-back for this binding's effect, over the gateway's own upstream session (P1b-7).

        The read is the gateway's, with its credentials, not an agent action, so the monitor
        does not decide it. Its outcome is recorded in the audit as the effect's confidence.
        """
        spec = binding.effect.confirm
        if spec is None:
            return {}
        return {binding.effect.kind: MCPReadBackReconciler(self.sessions[spec.server_id], spec.tool_name,
                                                           arguments=spec.arguments, expect=spec.expect)}

    def _refusal(self, kind: GatewayOutcomeKind, reasons: tuple[str, ...],
                 request: str | None = None) -> GatewayOutcome:
        message = kind.value
        if request is not None:
            message += f"; request {request} is waiting for an operator"
        if self.reason_disclosure == "reasons" and reasons:
            message += ": " + ", ".join(reasons)
        return GatewayOutcome(kind, message, approval_request=request, reasons=reasons)

    def _request_approval(self, action: PlannedAction, contract: TaskContract) -> str | None:
        """Write the action an operator is asked to approve, and return the request id.

        The file holds argument values, because an approver has to see what they are
        approving. It belongs in an operator-only directory, like the contracts.
        """
        try:
            fingerprint = action_fingerprint(action)
        except ValueError:
            return None
        identity = (contract.principal_id, contract.session_id, contract.tenant_id, contract.capability_id)
        request_id = hashlib.sha256(json.dumps([fingerprint, *identity]).encode("utf-8")).hexdigest()[:24]
        body = {
            "version": 1,
            "request_id": request_id,
            "tool": action.tool,
            "arguments": action.plain_arguments(),
            "action_fingerprint": fingerprint,
            "principal_id": contract.principal_id,
            "session_id": contract.session_id,
            "tenant_id": contract.tenant_id,
            "capability_id": contract.capability_id,
        }
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        path = self.pending_dir / f"{request_id}.json"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(_plain(body), indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(path)
        self.audit.record("approval_requested", tool=action.tool,
                          details={"request_id": request_id, "action_fingerprint": fingerprint,
                                   "principal_id": contract.principal_id, "session_id": contract.session_id,
                                   "tenant_id": contract.tenant_id, "capability_id": contract.capability_id})
        return request_id

    def _flush_audit(self) -> None:
        if self.audit_path is None:
            return
        with self._lock:
            events = self.audit.to_jsonl().splitlines()
            new = events[self._flushed:]
            if not new:
                return
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(new) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._flushed = len(events)


# --- the operator's side ------------------------------------------------------------

def grant_pending_request(
    request_path: str | Path,
    registry: ContractRegistry,
    store: ApprovalStore,
    *,
    ttl_seconds: float | None = None,
) -> str:
    """Approve one pending request: grant it in the store and remove the request.

    Run by an operator, never by the gateway. The grant is bound to the exact action and
    to the requesting contract's identity, so the agent's retry of the same call consumes
    it and any other call does not. Returns the action fingerprint.
    """
    path = Path(request_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise PolicyValidationError(f"{path}: not a version 1 approval request")
    contract = registry.find_identity(raw["principal_id"], raw["session_id"], raw["tenant_id"], raw["capability_id"])
    if contract is None:
        raise PolicyValidationError(f"{path}: the requesting contract is no longer registered")
    arguments = raw.get("arguments")
    if not isinstance(arguments, dict):
        raise PolicyValidationError(f"{path}: arguments must be a mapping")
    # The fingerprint covers the tool and the plain values only, so the label chosen here
    # does not change what is granted.
    action = PlannedAction(raw["tool"], {name: TrustedValue(value, source="operator")
                                         for name, value in arguments.items()})
    if action_fingerprint(action) != raw.get("action_fingerprint"):
        raise PolicyValidationError(f"{path}: the request's fingerprint does not match its action")
    store.grant(action, contract, ttl_seconds=ttl_seconds)
    path.unlink()
    return raw["action_fingerprint"]


def resolve_indeterminate_call(pending_dir: str | Path, call_id: str, outcome: str, *, by: str) -> Path:
    """Record an operator's finding about a consequential call whose outcome was unknown.

    Run by an operator after checking the backend, never by the gateway. ``outcome`` is
    ``happened`` or ``did_not_happen``. The gateway applies it at the session's next call to the
    tool: ``happened`` settles the call; ``did_not_happen`` stops it holding the tool and lets its
    exact retry be decided as the same call. ``by`` names the operator, as recorded; it is not
    authenticated (R4 in docs/workflow-integration-inventory.md). Returns the file written.
    """
    if outcome not in RESOLUTION_OUTCOMES:
        raise PolicyValidationError(f"outcome must be one of: {', '.join(RESOLUTION_OUTCOMES)}")
    if not isinstance(by, str) or not by.strip():
        raise PolicyValidationError("the operator's name is required")
    if not re.fullmatch(r"[0-9a-f]{32}", call_id or ""):
        raise PolicyValidationError("a call id is 32 hexadecimal characters, as the audit records it")
    directory = Path(pending_dir) / INDETERMINATE_DIR
    entry = directory / f"{call_id}.json"
    if not entry.exists():
        raise PolicyValidationError(f"no unresolved call {call_id} in {directory}")
    IndeterminateCall.load(entry)
    path = directory / f"{call_id}.resolution.json"
    write_json_atomic(path, {"version": 1, "call_id": call_id, "outcome": outcome, "by": by.strip(),
                             "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    return path


class _Unreadable(Exception):
    pass


def _identity_details(identity: tuple[str, ...]) -> dict[str, str]:
    return dict(zip(("principal_id", "session_id", "tenant_id", "capability_id"), identity))


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, frozenset, set)):
        return [_plain(item) for item in value]
    return value


def _iso(seconds: float | None) -> str | None:
    return None if seconds is None else datetime.fromtimestamp(seconds, timezone.utc).isoformat()
