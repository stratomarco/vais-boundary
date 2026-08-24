from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol
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
)
from .monitor import ReferenceMonitor
from .sandbox import Effect


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
class MCPEffectMapping:
    """Map an executed MCP tool to an observable VAIS effect.

    ``argument_fields`` maps effect field -> MCP argument name. If omitted, a
    generic ``mcp_tool_called`` effect is emitted with all original arguments.
    """

    kind: str = "mcp_tool_called"
    argument_fields: dict[str, str] = field(default_factory=dict)

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
        object.__setattr__(self, "kind", unicodedata.normalize("NFC", self.kind))
        object.__setattr__(self, "argument_fields", FrozenDict(fields))


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
    ) -> None:
        if not server_id.strip():
            raise ValueError("server_id must be a non-empty string")
        self.server_id = unicodedata.normalize("NFC", server_id)
        self.session = session
        self.profile = profile
        self.monitor = monitor

    async def execute(self, action: PlannedAction, contract: TaskContract) -> MCPExecutionRecord:
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

        decision = self.monitor.evaluate(action, contract)
        if decision.type != DecisionType.ALLOW:
            return MCPExecutionRecord(
                action, binding, decision, None, None, MCPCallState.NOT_CALLED
            )

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
        result_data = extract_mcp_result_data(raw_result)
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
        _fail(path, f"unknown field(s): {', '.join(sorted(unknown))}")


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
                canonical = canonical_mcp_tool(server_id, tool_name)
            canonical = _string(canonical, f"{tool_path}.canonical_tool")

            result_conf = _confidentiality(
                tool_raw.get("result_confidentiality", default_conf.value),
                f"{tool_path}.result_confidentiality",
            )

            effect_raw = _mapping(tool_raw.get("effect", {}), f"{tool_path}.effect")
            _known_keys(effect_raw, {"kind", "argument_fields"}, f"{tool_path}.effect")
            effect_kind = _string(
                effect_raw.get("kind", "mcp_tool_called"), f"{tool_path}.effect.kind"
            )
            field_raw = _mapping(
                effect_raw.get("argument_fields", {}), f"{tool_path}.effect.argument_fields"
            )
            fields: dict[str, str] = {}
            for effect_field, argument_name in field_raw.items():
                fields[
                    _string(effect_field, f"{tool_path}.effect.argument_fields.<effect_field>")
                ] = _string(
                    argument_name,
                    f"{tool_path}.effect.argument_fields.{effect_field}",
                )

            bindings.append(
                MCPToolBinding(
                    server_id=server_id,
                    tool_name=tool_name,
                    canonical_tool=canonical,
                    result_policy=MCPResultPolicy(result_conf),
                    effect=MCPEffectMapping(effect_kind, fields),
                )
            )

    try:
        return MCPProfile(tuple(bindings), version=version)
    except ValueError as exc:
        _fail("mcp_profile", str(exc))
    raise AssertionError("unreachable")
