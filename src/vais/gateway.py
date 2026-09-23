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

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Mapping

import yaml

from .approvals import ApprovalStore
from .audit import AuditTrail
from .exceptions import PolicyValidationError
from .ledger import SessionLedger
from .mcp import (
    MCPCallState,
    MCPProfile,
    MCPProtectedClient,
    MCPToolBinding,
    MCPToolSession,
    _confidentiality,
    _fail,
    _known_keys,
    _mapping,
    _string,
)
from .models import (
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
)
from .monitor import ReferenceMonitor

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
    "not_before", "not_after",
}


def load_gateway_contract(path: str | Path) -> tuple[str, TaskContract]:
    """Load one operator-owned contract file: the token digest and the contract it grants.

    Parsed strictly, like every VAIS security file. Bound values are trusted with source
    ``contract`` and may carry a confidentiality level:
    ``bound_arguments: {tool: {argument: value}}`` or
    ``{tool: {argument: {value: ..., confidentiality: secret}}}``.
    """
    location = str(path)
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
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
        contracts: dict[str, TaskContract] = {}
        duplicates: set[str] = set()
        problems: list[str] = []
        for path in sorted(self.directory.glob("*.yaml")):
            try:
                digest, contract = load_gateway_contract(path)
            except PolicyValidationError as exc:
                problems.append(str(exc))
                continue
            if digest in contracts:
                duplicates.add(digest)
            contracts[digest] = contract
        for digest in duplicates:
            contracts.pop(digest)
            problems.append(f"token digest {digest[:12]}... appears in more than one contract; none apply")
        return contracts, tuple(problems)

    def lookup(self, token: str) -> TaskContract | None:
        if not isinstance(token, str) or not token:
            return None
        contracts, _ = self.scan()
        return contracts.get(token_digest(token))

    def find_identity(self, principal_id: str, session_id: str, tenant_id: str,
                      capability_id: str) -> TaskContract | None:
        contracts, _ = self.scan()
        identity = (principal_id, session_id, tenant_id, capability_id)
        return next((c for c in contracts.values()
                     if (c.principal_id, c.session_id, c.tenant_id, c.capability_id) == identity), None)


# --- labelling ---------------------------------------------------------------------

def label_agent_action(
    tool: str,
    arguments: Mapping[str, Any],
    contract: TaskContract,
    context_level: ConfidentialityLevel,
) -> PlannedAction:
    """Build the ``PlannedAction`` for arguments that arrived from the agent.

    Nothing the agent sends is trusted on its say-so. An argument exactly equal to its
    contract binding takes the binding's label, since its value is the one the operator
    wrote; every other argument is model output at the session's confidentiality level.
    """
    values: dict[str, Value] = {}
    for name, data in arguments.items():
        bound = contract.bound_arguments.get((tool, name))
        if bound is not None and security_equal(deep_freeze(data), bound.data):
            values[name] = Value(data, bound.provenance)
        else:
            values[name] = Value(data, Provenance(
                source="model_output", trust=TrustLevel.DERIVED_UNTRUSTED, confidentiality=context_level,
            ))
    return PlannedAction(tool, values)


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


@dataclass
class _SessionState:
    ledger: SessionLedger
    context_level: ConfidentialityLevel = ConfidentialityLevel.PUBLIC


@dataclass(frozen=True)
class ExposedTool:
    name: str
    binding: MCPToolBinding


def exposed_name(binding: MCPToolBinding) -> str:
    return f"{binding.server_id}.{binding.tool_name}"


# --- the gateway ---------------------------------------------------------------------

class Gateway:
    """Decide and forward calls for agents that hold a session token and nothing else.

    ``sessions`` maps each upstream ``server_id`` to a live MCP client session that the
    gateway opened with the upstream's credentials. ``reason_disclosure`` controls what a
    refused agent is told: ``"decision"`` (the default) gives the outcome only, so denials
    are not a probing oracle (S13, IMP-003); ``"reasons"`` adds the monitor's reason codes.
    The audit trail always keeps them.
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
    ) -> None:
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
            tools[name] = ExposedTool(name, binding)
        self._tools = tools

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
                state = self._states[key] = _SessionState(SessionLedger(contract))
            return state

    async def call(self, token: str, name: str, arguments: Mapping[str, Any] | None) -> GatewayOutcome:
        try:
            return await self._call(token, name, dict(arguments or {}))
        finally:
            self._flush_audit()

    async def _call(self, token: str, name: str, arguments: dict[str, Any]) -> GatewayOutcome:
        contract = self.registry.lookup(token)
        if contract is None:
            # Nothing about the token is recorded; its digest would help an attacker more
            # than the operator.
            self.audit.record("gateway_unauthenticated", tool=name if isinstance(name, str) else None)
            return GatewayOutcome(GatewayOutcomeKind.UNAUTHENTICATED, "unauthenticated")

        exposed = self._tools.get(name)
        if exposed is None or exposed.binding.canonical_tool not in contract.allowed_tools:
            self.audit.record("gateway_unknown_tool", tool=name if isinstance(name, str) else None,
                              decision=DecisionType.DENY.value, reasons=("tool_not_exposed",),
                              details={"principal_id": contract.principal_id, "session_id": contract.session_id,
                                       "tenant_id": contract.tenant_id, "capability_id": contract.capability_id})
            return self._refusal(GatewayOutcomeKind.DENIED, ("tool_not_exposed",))

        binding = exposed.binding
        state = self._state(contract)
        try:
            action = label_agent_action(binding.canonical_tool, arguments, contract, state.context_level)
        except ValueError:
            self.audit.record("gateway_malformed_arguments", tool=binding.canonical_tool,
                              decision=DecisionType.DENY.value, reasons=("malformed_arguments",))
            return self._refusal(GatewayOutcomeKind.DENIED, ("malformed_arguments",))

        client = MCPProtectedClient(
            server_id=binding.server_id,
            session=self.sessions[binding.server_id],
            profile=self.profile,
            monitor=self.monitor,
            approval_store=self.approval_store,
            audit=self.audit,
            ledger=state.ledger,
        )
        record = await client.execute(action, contract)

        if record.call_state is MCPCallState.OBSERVED:
            level = binding.result_policy.confidentiality
            with self._lock:
                if level.rank > state.context_level.rank:
                    state.context_level = level
            return GatewayOutcome(GatewayOutcomeKind.ALLOWED, "ok", result=record.result.data if record.result else None)
        if record.call_state is MCPCallState.INDETERMINATE:
            return GatewayOutcome(GatewayOutcomeKind.INDETERMINATE,
                                  "the call was dispatched and failed; its effect is unknown")
        if record.decision.type is DecisionType.REQUIRE_APPROVAL:
            request = self._request_approval(action, contract)
            return self._refusal(GatewayOutcomeKind.APPROVAL_REQUIRED, record.decision.reasons, request)
        return self._refusal(GatewayOutcomeKind.DENIED, record.decision.reasons)

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


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, frozenset, set)):
        return [_plain(item) for item in value]
    return value
