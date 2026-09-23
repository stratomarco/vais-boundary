from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol
import unicodedata

import yaml

from .exceptions import PolicyValidationError
from .models import (
    ConfidentialityLevel,
    Decision,
    DecisionType,
    PlannedAction,
    Provenance,
    TaskContract,
    TrustLevel,
    Value,
    FrozenDict,
    action_fingerprint,
    deep_freeze,
    security_equal,
)
from .approvals import ApprovalStore
from .audit import AuditTrail, action_audit_details
from .ledger import SessionLedger
from .monitor import ReferenceMonitor
from .sandbox import Effect, EffectConfidence


class MCPToolSession(Protocol):
    """Minimal protocol implemented by the official MCP ClientSession.

    VAIS deliberately depends on this tiny behavioral interface rather than on
    MCP SDK types in its core package. The optional ``mcp`` extra is therefore
    only needed by applications that want live protocol transports.
    """

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any: ...


@dataclass(frozen=True)
class MCPResultPolicy:
    """Security labels applied to data returned from an MCP primitive.

    Direct MCP output is never authority by default. v0.7 intentionally does
    not provide a profile switch that upgrades remote result data to TRUSTED;
    applications that truly need authority must construct it through a trusted
    application-specific adapter outside the model/MCP data path.
    """

    confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC


@dataclass(frozen=True)
class MCPReadBackSpec:
    """Where to read an effect back from (P1b-7): a tool on a server, what to pass, what to compare."""

    server_id: str
    tool_name: str
    arguments: dict[str, str] = field(default_factory=dict)
    expect: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, value in {"server_id": self.server_id, "tool_name": self.tool_name}.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"confirm.{label} must be a non-empty string")
        if not self.expect:
            raise ValueError("confirm.expect must name at least one field")
        for name, source in self.arguments.items():
            if not isinstance(source, str) or not source.startswith(("effect.", "reply.")):
                raise ValueError(f"confirm.arguments.{name} must be effect.<field> or reply.<field>")
        object.__setattr__(self, "arguments", FrozenDict(dict(self.arguments)))
        object.__setattr__(self, "expect", FrozenDict(dict(self.expect)))


@dataclass(frozen=True)
class MCPEffectMapping:
    """Map an executed MCP tool to an observable VAIS effect.

    ``argument_fields`` maps effect field -> MCP argument name. If omitted, a
    generic ``mcp_tool_called`` effect is emitted with all original arguments.
    """

    kind: str = "mcp_tool_called"
    argument_fields: dict[str, str] = field(default_factory=dict)
    # effect field -> top-level field of the server's structured reply that must repeat it
    # for the effect to count as acknowledged (P1b-7). A reply that reports a different
    # value contradicts the effect.
    acknowledge: dict[str, str] = field(default_factory=dict)
    confirm: MCPReadBackSpec | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise ValueError("effect kind must be a non-empty string")
        fields: dict[str, str] = {}
        for effect_field, argument_name in self.argument_fields.items():
            if not isinstance(effect_field, str) or not effect_field.strip():
                raise ValueError("effect field names must be non-empty strings")
            if not isinstance(argument_name, str) or not argument_name.strip():
                raise ValueError("effect argument names must be non-empty strings")
            normalized_field = unicodedata.normalize("NFC", effect_field)
            if normalized_field in fields:
                raise ValueError("Unicode normalization produced a duplicate effect field")
            fields[normalized_field] = unicodedata.normalize("NFC", argument_name)
        acknowledge: dict[str, str] = {}
        for effect_field, reply_field in self.acknowledge.items():
            if not isinstance(effect_field, str) or not effect_field.strip() or not isinstance(reply_field, str) or not reply_field.strip():
                raise ValueError("acknowledge maps non-empty effect field names to non-empty reply field names")
            normalized = unicodedata.normalize("NFC", effect_field)
            if fields and normalized not in fields:
                raise ValueError(f"acknowledge names {normalized!r}, which is not an effect field")
            acknowledge[normalized] = unicodedata.normalize("NFC", reply_field)
        object.__setattr__(self, "kind", unicodedata.normalize("NFC", self.kind))
        object.__setattr__(self, "argument_fields", FrozenDict(fields))
        object.__setattr__(self, "acknowledge", FrozenDict(acknowledge))


@dataclass(frozen=True)
class MCPToolBinding:
    server_id: str
    tool_name: str
    canonical_tool: str
    result_policy: MCPResultPolicy = field(default_factory=MCPResultPolicy)
    effect: MCPEffectMapping = field(default_factory=MCPEffectMapping)

    def __post_init__(self) -> None:
        for label, value in {
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "canonical_tool": self.canonical_tool,
            "effect.kind": self.effect.kind,
        }.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} must be a non-empty string")
        object.__setattr__(self, "server_id", unicodedata.normalize("NFC", self.server_id))
        object.__setattr__(self, "tool_name", unicodedata.normalize("NFC", self.tool_name))
        object.__setattr__(
            self, "canonical_tool", unicodedata.normalize("NFC", self.canonical_tool)
        )


@dataclass(frozen=True)
class MCPProfile:
    bindings: tuple[MCPToolBinding, ...]
    version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "bindings", tuple(self.bindings))
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version != 1:
            raise ValueError("MCP profile version must be 1")
        canonical = [item.canonical_tool for item in self.bindings]
        endpoints = [(item.server_id, item.tool_name) for item in self.bindings]
        if len(canonical) != len(set(canonical)):
            raise ValueError("MCP canonical tool names must be unique")
        if len(endpoints) != len(set(endpoints)):
            raise ValueError("MCP server/tool bindings must be unique")

    def by_canonical_tool(self, tool: str) -> MCPToolBinding | None:
        return next((item for item in self.bindings if item.canonical_tool == tool), None)

    def by_endpoint(self, server_id: str, tool_name: str) -> MCPToolBinding | None:
        return next(
            (
                item
                for item in self.bindings
                if item.server_id == server_id and item.tool_name == tool_name
            ),
            None,
        )

    def exposed_tools(self, contract: TaskContract, *, server_id: str | None = None) -> tuple[MCPToolBinding, ...]:
        """Return the least-exposure catalog for a task.

        Catalog filtering reduces model attack surface, but it is *not* the
        authorization boundary. Every eventual call is still mediated by the
        reference monitor.
        """

        return tuple(
            item
            for item in self.bindings
            if item.canonical_tool in contract.allowed_tools
            and (server_id is None or item.server_id == server_id)
        )


@dataclass(frozen=True)
class Reconciliation:
    """What a read-back from the system of record established about one effect (P1b-7).

    ``confidence`` is ``confirmed`` when every checked field agrees, ``contradicted`` when
    any disagrees, and ``requested`` when the read-back could not tell.
    """

    confidence: EffectConfidence
    contradicted_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.confidence is EffectConfidence.ACKNOWLEDGED:
            raise ValueError("a read-back confirms, contradicts or cannot tell; it does not acknowledge")


class EffectReconciler(Protocol):
    """Reads an effect back from its system of record, by a path the executing server does not control."""

    async def reconcile(self, effect: Effect, reply: Any) -> Reconciliation: ...


def acknowledge_effect(effect: Effect, acknowledge: Mapping[str, str], reply: Any) -> Effect:
    """Raise an effect to ``acknowledged``, or mark it ``contradicted``, from the server's reply.

    Each effect field in ``acknowledge`` must appear in the structured reply under its
    mapped name with the value requested. A reply that names a field with another value
    contradicts the effect. A reply that omits one leaves the effect ``requested``. The reply
    is the server's own claim: a server that lies consistently is not caught here (LIM-065).
    """
    if not acknowledge or not isinstance(reply, dict):
        return effect
    contradicted, missing = [], False
    for effect_field, reply_field in acknowledge.items():
        if reply_field not in reply:
            missing = True
        elif not security_equal(deep_freeze(reply[reply_field]), effect.attributes.get(effect_field)):
            contradicted.append(effect_field)
    if contradicted:
        return replace(effect, confidence=EffectConfidence.CONTRADICTED, contradicted_fields=tuple(contradicted))
    if missing:
        return effect
    return replace(effect, confidence=EffectConfidence.ACKNOWLEDGED)


def apply_reconciliation(effect: Effect, outcome: Reconciliation) -> Effect:
    """Combine a read-back with what the effect already carries. A contradiction always wins."""
    if outcome.confidence is EffectConfidence.CONTRADICTED or effect.confidence is EffectConfidence.CONTRADICTED:
        fields = tuple(set(effect.contradicted_fields) | set(outcome.contradicted_fields))
        return replace(effect, confidence=EffectConfidence.CONTRADICTED, contradicted_fields=fields)
    if outcome.confidence is EffectConfidence.CONFIRMED:
        return replace(effect, confidence=EffectConfidence.CONFIRMED)
    return effect


class MCPReadBackReconciler:
    """Confirm an effect by calling a read tool, preferably on the system of record's own server.

    ``arguments`` maps each read-back argument to ``effect.<field>`` or ``reply.<field>``; an id
    the executing server returned may be used to find the record, since what is compared is
    the record, not the reply. ``expect`` maps effect fields to fields of the read-back result.
    Reading back through the same server that executed the effect only moves the trust to
    that server (LIM-065).
    """

    def __init__(self, session: MCPToolSession, tool_name: str, *,
                 arguments: Mapping[str, str], expect: Mapping[str, str]) -> None:
        if not expect:
            raise ValueError("a read-back needs at least one expected field")
        for name, source in arguments.items():
            if not isinstance(source, str) or not source.startswith(("effect.", "reply.")):
                raise ValueError(f"read-back argument {name!r} must come from effect.<field> or reply.<field>")
        self.session = session
        self.tool_name = tool_name
        self.arguments = dict(arguments)
        self.expect = dict(expect)

    async def reconcile(self, effect: Effect, reply: Any) -> Reconciliation:
        unknown = Reconciliation(EffectConfidence.REQUESTED)
        call: dict[str, Any] = {}
        for name, source in self.arguments.items():
            scope, _, key = source.partition(".")
            holder = effect.attributes if scope == "effect" else (reply if isinstance(reply, dict) else {})
            if key not in holder:
                return unknown
            call[name] = _thaw(holder[key])
        record = extract_mcp_result_data(await self.session.call_tool(self.tool_name, call))
        if not isinstance(record, dict):
            return unknown
        contradicted, missing = [], False
        for effect_field, record_field in self.expect.items():
            if record_field not in record:
                missing = True
            elif not security_equal(deep_freeze(record[record_field]), effect.attributes.get(effect_field)):
                contradicted.append(effect_field)
        if contradicted:
            return Reconciliation(EffectConfidence.CONTRADICTED, tuple(contradicted))
        return unknown if missing else Reconciliation(EffectConfidence.CONFIRMED)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


class MCPCallState(str, Enum):
    NOT_CALLED = "not_called"
    OBSERVED = "observed"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class MCPExecutionRecord:
    action: PlannedAction
    binding: MCPToolBinding | None
    decision: Decision
    effect: Effect | None
    result: Value | None
    call_state: MCPCallState = MCPCallState.NOT_CALLED
    error: str | None = None
    request_id: str | None = None
    retry_safe: bool = False


def canonical_mcp_tool(server_id: str, tool_name: str) -> str:
    """Create a collision-resistant human-readable MCP tool namespace."""

    for label, value in {"server_id": server_id, "tool_name": tool_name}.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
        if ":" in value:
            raise ValueError(f"{label} cannot contain ':'")
    server_id = unicodedata.normalize("NFC", server_id)
    tool_name = unicodedata.normalize("NFC", tool_name)
    return f"mcp:{server_id}:{tool_name}"


def label_mcp_input(
    data: Any,
    *,
    server_id: str,
    primitive: str,
    name: str,
    confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC,
) -> Value:
    """Label MCP-originated data as non-authoritative input.

    This is intentionally fail-safe: a tool/resource/prompt can carry useful
    data, but merely coming from an MCP server does not grant it authority over
    consequential actions.
    """

    for label, value in {"server_id": server_id, "primitive": primitive, "name": name}.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
    server_id = unicodedata.normalize("NFC", server_id)
    primitive = unicodedata.normalize("NFC", primitive)
    name = unicodedata.normalize("NFC", name)
    return Value(
        data,
        Provenance(
            source=f"mcp:{server_id}:{primitive}:{name}",
            trust=TrustLevel.UNTRUSTED,
            confidentiality=confidentiality,
        ),
    )


class MCPProtectedClient:
    """Reference-monitor wrapper around one live MCP client session.

    The model/agent supplies a ``PlannedAction``. VAIS decides whether that
    action is authorized. Only ``ALLOW`` is forwarded to ``session.call_tool``.
    ``DENY`` and ``REQUIRE_APPROVAL`` never reach the MCP server.

    Pass an ``approval_store`` for consume-once approvals. Without one the monitor
    falls back to the contract's approved fingerprints, which authorize an exact
    action for as long as the contract is in use unless a ``ledger`` is also passed
    (LIM-044). Before rc12 this client could not take a store at all, so
    consume-once never held on the MCP path (FIND-049). A ``ledger`` also enforces
    ``max_calls`` and gives VERIFY the record of what was allowed.

    The wrapper is intentionally small. It is suitable for an agent host that
    already owns an MCP ``ClientSession``. A fully transparent protocol proxy
    for arbitrary hosts is a future integration layer, not implied here.
    """

    def __init__(
        self,
        *,
        server_id: str,
        session: MCPToolSession,
        profile: MCPProfile,
        monitor: ReferenceMonitor,
        approval_store: ApprovalStore | None = None,
        audit: AuditTrail | None = None,
        ledger: SessionLedger | None = None,
        reconcilers: Mapping[str, EffectReconciler] | None = None,
    ) -> None:
        if not server_id.strip():
            raise ValueError("server_id must be a non-empty string")
        self.server_id = unicodedata.normalize("NFC", server_id)
        self.session = session
        self.profile = profile
        self.monitor = monitor
        self.approval_store = approval_store
        self.audit = audit
        self.ledger = ledger
        # effect kind -> reconciler that reads it back from the system of record (P1b-7)
        self.reconcilers = dict(reconcilers or {})

    def _audit_decision(
        self, action: PlannedAction, contract: TaskContract, decision: Decision
    ) -> None:
        if self.audit:
            self.audit.record(
                "authorization_decision",
                tool=action.tool,
                decision=decision.type.value,
                reasons=decision.reasons,
                details=action_audit_details(action, contract),
            )

    async def execute(self, action: PlannedAction, contract: TaskContract) -> MCPExecutionRecord:
        try:
            request_id = action_fingerprint(action)
        except ValueError:
            request_id = None
        binding = self.profile.by_canonical_tool(action.tool)
        if binding is None:
            decision = Decision(DecisionType.DENY, (f"mcp_binding_missing:{action.tool}",))
            self._audit_decision(action, contract, decision)
            return MCPExecutionRecord(
                action=action,
                binding=None,
                decision=decision,
                effect=None,
                result=None,
                call_state=MCPCallState.NOT_CALLED,
            )
        if binding.server_id != self.server_id:
            decision = Decision(
                DecisionType.DENY,
                (f"mcp_server_mismatch:{binding.server_id}!={self.server_id}",),
            )
            self._audit_decision(action, contract, decision)
            return MCPExecutionRecord(
                action=action,
                binding=binding,
                decision=decision,
                effect=None,
                result=None,
                call_state=MCPCallState.NOT_CALLED,
            )

        decision = self.monitor.evaluate(action, contract, self.approval_store, self.ledger)
        self._audit_decision(action, contract, decision)
        if decision.type != DecisionType.ALLOW:
            return MCPExecutionRecord(
                action, binding, decision, None, None, MCPCallState.NOT_CALLED
            )

        try:
            raw_result = await self.session.call_tool(binding.tool_name, action.plain_arguments())
        except Exception as exc:
            if self.audit:
                # The exception class only. Messages can carry secrets (FIND-020, FIND-040).
                self.audit.record(
                    "effect_indeterminate",
                    tool=action.tool,
                    details={"error": type(exc).__name__, "action_fingerprint": request_id},
                )
            return MCPExecutionRecord(
                action=action,
                binding=binding,
                decision=decision,
                effect=None,
                result=None,
                call_state=MCPCallState.INDETERMINATE,
                error=type(exc).__name__,
                request_id=request_id,
                retry_safe=False,
            )

        result_data = extract_mcp_result_data(raw_result)
        effect = acknowledge_effect(_effect_from_binding(action, binding), binding.effect.acknowledge, result_data)
        reconciler = self.reconcilers.get(effect.kind)
        if reconciler is not None:
            try:
                effect = apply_reconciliation(effect, await reconciler.reconcile(effect, result_data))
            except Exception as exc:
                # The effect happened; only what is known about it is unchanged.
                if self.audit:
                    self.audit.record("reconciliation_failed", tool=action.tool,
                                      details={"error": type(exc).__name__, "action_fingerprint": request_id})
        if self.audit:
            self.audit.record(
                "effect_observed",
                tool=action.tool,
                details={
                    "effect": effect.kind,
                    "fields": sorted(effect.attributes),
                    "action_fingerprint": effect.action_fingerprint,
                    "confidence": effect.confidence.value,
                    "contradicted_fields": list(effect.contradicted_fields),
                },
            )
        result = label_mcp_input(
            result_data,
            server_id=binding.server_id,
            primitive="tool_result",
            name=binding.tool_name,
            confidentiality=binding.result_policy.confidentiality,
        )
        return MCPExecutionRecord(
            action, binding, decision, effect, result, MCPCallState.OBSERVED,
            request_id=request_id
        )


class MCPUnprotectedClient:
    """Deliberately unsafe MCP execution path used only for assessment baselines.

    This class exists so VAIS experiments can demonstrate whether the same
    model-generated action produces an observable effect without the reference
    monitor. Do not use it as a production agent client.
    """

    def __init__(
        self,
        *,
        server_id: str,
        session: MCPToolSession,
        profile: MCPProfile,
    ) -> None:
        if not server_id.strip():
            raise ValueError("server_id must be a non-empty string")
        self.server_id = unicodedata.normalize("NFC", server_id)
        self.session = session
        self.profile = profile

    async def execute(self, action: PlannedAction) -> MCPExecutionRecord:
        try:
            request_id = action_fingerprint(action)
        except ValueError:
            request_id = None
        binding = self.profile.by_canonical_tool(action.tool)
        if binding is None:
            return MCPExecutionRecord(
                action=action,
                binding=None,
                decision=Decision(DecisionType.DENY, (f"mcp_binding_missing:{action.tool}",)),
                effect=None,
                result=None,
                call_state=MCPCallState.NOT_CALLED,
            )
        if binding.server_id != self.server_id:
            return MCPExecutionRecord(
                action=action,
                binding=binding,
                decision=Decision(
                    DecisionType.DENY,
                    (f"mcp_server_mismatch:{binding.server_id}!={self.server_id}",),
                ),
                effect=None,
                result=None,
                call_state=MCPCallState.NOT_CALLED,
            )

        decision = Decision(DecisionType.ALLOW, ("unprotected_mcp_bypass",))
        try:
            raw_result = await self.session.call_tool(binding.tool_name, action.plain_arguments())
        except Exception as exc:
            return MCPExecutionRecord(
                action=action,
                binding=binding,
                decision=decision,
                effect=None,
                result=None,
                call_state=MCPCallState.INDETERMINATE,
                error=type(exc).__name__,
                request_id=request_id,
                retry_safe=False,
            )

        effect = _effect_from_binding(action, binding)
        result = label_mcp_input(
            extract_mcp_result_data(raw_result),
            server_id=binding.server_id,
            primitive="tool_result",
            name=binding.tool_name,
            confidentiality=binding.result_policy.confidentiality,
        )
        return MCPExecutionRecord(
            action, binding, decision, effect, result, MCPCallState.OBSERVED
        )


def extract_mcp_result_data(raw_result: Any) -> Any:
    """Extract useful data without importing MCP SDK types into VAIS core."""

    if raw_result is None:
        return None
    if isinstance(raw_result, (str, int, float, bool, list, dict)):
        return raw_result

    for attribute in ("structuredContent", "structured_content"):
        value = getattr(raw_result, attribute, None)
        if value is not None:
            return value

    content = getattr(raw_result, "content", None)
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            text = getattr(item, "text", None)
            if isinstance(text, str):
                text_parts.append(text)
        if text_parts:
            return "\n".join(text_parts)

    return str(raw_result)


def _effect_from_binding(action: PlannedAction, binding: MCPToolBinding) -> Effect:
    plain = action.plain_arguments()
    if binding.effect.argument_fields:
        attributes = {
            effect_field: plain.get(argument_name)
            for effect_field, argument_name in binding.effect.argument_fields.items()
        }
        provenance = {
            effect_field: action.arguments[argument_name].provenance
            for effect_field, argument_name in binding.effect.argument_fields.items()
            if argument_name in action.arguments
        }
    else:
        attributes = {
            "server_id": binding.server_id,
            "tool_name": binding.tool_name,
            **plain,
        }
        provenance = {name: value.provenance for name, value in action.arguments.items()}

    try:
        fingerprint = action_fingerprint(action)
    except ValueError:
        fingerprint = None

    return Effect(
        binding.effect.kind,
        attributes,
        provenance,
        tool=action.tool,
        action_fingerprint=fingerprint,
        origin=action.origin,
    )


def _fail(path: str, message: str) -> None:
    raise PolicyValidationError(f"{path}: {message}")


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be a mapping")
    return value


def _known_keys(raw: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        # YAML keys are not necessarily strings. `1: x`, `true: x` and `~: x` all
        # produce non-string keys, and sorting or joining them raised TypeError
        # here instead of reporting an unknown field (FIND-048). Rendering through
        # str() keeps the message useful and the rejection in contract.
        rendered = ", ".join(sorted(str(key) for key in unknown))
        _fail(path, f"unknown field(s): {rendered}")


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(path, "must be a non-empty string")
    return unicodedata.normalize("NFC", value)


def _confidentiality(value: Any, path: str) -> ConfidentialityLevel:
    try:
        return ConfidentialityLevel(value)
    except (TypeError, ValueError):
        allowed = ", ".join(item.value for item in ConfidentialityLevel)
        _fail(path, f"must be one of: {allowed}")
    raise AssertionError("unreachable")


def load_mcp_profile(path: str | Path) -> MCPProfile:
    """Load a strict MCP integration profile.

    Schema v1 deliberately permits confidentiality labeling but does not allow
    remote MCP results to be configured as ``trusted`` authority.
    """

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    raw = _mapping(raw, "mcp_profile")
    _known_keys(raw, {"version", "servers"}, "mcp_profile")
    version = raw.get("version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        _fail("mcp_profile.version", "only version 1 is supported")

    servers = _mapping(raw.get("servers", {}), "mcp_profile.servers")
    bindings: list[MCPToolBinding] = []
    for server_id, server_raw in servers.items():
        _string(server_id, "mcp_profile.servers.<server_id>")
        server_path = f"mcp_profile.servers.{server_id}"
        server_raw = _mapping(server_raw, server_path)
        _known_keys(server_raw, {"default_confidentiality", "tools"}, server_path)
        default_conf = _confidentiality(
            server_raw.get("default_confidentiality", "public"),
            f"{server_path}.default_confidentiality",
        )
        tools = _mapping(server_raw.get("tools", {}), f"{server_path}.tools")
        for tool_name, tool_raw in tools.items():
            _string(tool_name, f"{server_path}.tools.<tool_name>")
            tool_path = f"{server_path}.tools.{tool_name}"
            tool_raw = _mapping(tool_raw, tool_path)
            _known_keys(
                tool_raw,
                {"canonical_tool", "result_confidentiality", "effect"},
                tool_path,
            )
            canonical = tool_raw.get("canonical_tool")
            if canonical is None:
                try:
                    canonical = canonical_mcp_tool(server_id, tool_name)
                except ValueError as exc:
                    # A ':' in a server or tool name escaped as ValueError, outside
                    # this loader's contract (FIND-054).
                    _fail(tool_path, str(exc))
            canonical = _string(canonical, f"{tool_path}.canonical_tool")

            result_conf = _confidentiality(
                tool_raw.get("result_confidentiality", default_conf.value),
                f"{tool_path}.result_confidentiality",
            )

            effect_raw = _mapping(tool_raw.get("effect", {}), f"{tool_path}.effect")
            _known_keys(effect_raw, {"kind", "argument_fields", "acknowledge", "confirm"}, f"{tool_path}.effect")
            effect_kind = _string(
                effect_raw.get("kind", "mcp_tool_called"), f"{tool_path}.effect.kind"
            )
            field_raw = _mapping(
                effect_raw.get("argument_fields", {}), f"{tool_path}.effect.argument_fields"
            )
            fields: dict[str, str] = {}
            for effect_field, argument_name in field_raw.items():
                key = _string(effect_field, f"{tool_path}.effect.argument_fields.<effect_field>")
                # _string returns the NFC form, so two distinct YAML keys can meet here.
                # Assigning would let the later one silently replace the earlier, and
                # MCPEffectMapping's own duplicate check never sees them (FIND-055).
                if key in fields:
                    _fail(
                        f"{tool_path}.effect.argument_fields",
                        "Unicode normalization produced a duplicate effect field",
                    )
                fields[key] = _string(
                    argument_name,
                    f"{tool_path}.effect.argument_fields.{effect_field}",
                )

            acknowledge = {
                _string(k, f"{tool_path}.effect.acknowledge.<effect_field>"):
                _string(v, f"{tool_path}.effect.acknowledge.{k}")
                for k, v in _mapping(effect_raw.get("acknowledge", {}), f"{tool_path}.effect.acknowledge").items()
            }
            confirm = None
            if "confirm" in effect_raw:
                confirm_path = f"{tool_path}.effect.confirm"
                confirm_raw = _mapping(effect_raw["confirm"], confirm_path)
                _known_keys(confirm_raw, {"server", "tool", "arguments", "expect"}, confirm_path)

                def names(key: str) -> dict[str, str]:
                    return {_string(k, f"{confirm_path}.{key}.<name>"): _string(v, f"{confirm_path}.{key}.{k}")
                            for k, v in _mapping(confirm_raw.get(key, {}), f"{confirm_path}.{key}").items()}

                try:
                    confirm = MCPReadBackSpec(_string(confirm_raw.get("server"), f"{confirm_path}.server"),
                                              _string(confirm_raw.get("tool"), f"{confirm_path}.tool"),
                                              names("arguments"), names("expect"))
                except ValueError as exc:
                    if isinstance(exc, PolicyValidationError):
                        raise
                    _fail(confirm_path, str(exc))

            try:
                binding = MCPToolBinding(
                    server_id=server_id,
                    tool_name=tool_name,
                    canonical_tool=canonical,
                    result_policy=MCPResultPolicy(result_conf),
                    effect=MCPEffectMapping(effect_kind, fields, acknowledge, confirm),
                )
            except ValueError as exc:
                _fail(tool_path, str(exc))
            bindings.append(binding)

    try:
        return MCPProfile(tuple(bindings), version=version)
    except ValueError as exc:
        _fail("mcp_profile", str(exc))
    raise AssertionError("unreachable")
