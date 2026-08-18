from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
from collections.abc import Mapping
from typing import Any
import math
import unicodedata


class TrustLevel(str, Enum):
    """Integrity/provenance level for a value.

    TRUSTED means the value originated exclusively from an authority-bearing
    source accepted by the application. UNTRUSTED is raw attacker-controllable
    data. DERIVED_UNTRUSTED is data computed from one or more untrusted inputs.
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    DERIVED_UNTRUSTED = "derived_untrusted"


class ConfidentialityLevel(str, Enum):
    """Ordered confidentiality labels used for deterministic egress checks."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"

    @property
    def rank(self) -> int:
        return {
            ConfidentialityLevel.PUBLIC: 0,
            ConfidentialityLevel.INTERNAL: 1,
            ConfidentialityLevel.CONFIDENTIAL: 2,
            ConfidentialityLevel.SECRET: 3,
        }[self]


@dataclass(frozen=True)
class Provenance:
    source: str
    trust: TrustLevel
    detail: str | None = None
    confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC
    parents: tuple[str, ...] = ()


@dataclass(frozen=True)
class Value:
    data: Any
    provenance: Provenance

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", deep_freeze(self.data))

    @property
    def is_trusted(self) -> bool:
        return self.provenance.trust == TrustLevel.TRUSTED

    @property
    def confidentiality(self) -> ConfidentialityLevel:
        return self.provenance.confidentiality


class TrustedValue(Value):
    def __init__(
        self,
        data: Any,
        source: str = "trusted",
        confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC,
    ) -> None:
        super().__init__(
            data,
            Provenance(
                source=source,
                trust=TrustLevel.TRUSTED,
                confidentiality=confidentiality,
            ),
        )


@dataclass(frozen=True)
class PlannedAction:
    tool: str
    arguments: Mapping[str, Value]

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not self.tool.strip():
            raise ValueError("tool must be a non-empty string")
        values = dict(self.arguments)
        if any(not isinstance(k, str) or not k.strip() for k in values):
            raise ValueError("argument names must be non-empty strings")
        if any(not isinstance(v, Value) for v in values.values()):
            raise ValueError("action arguments must be Values")
        object.__setattr__(self, "tool", unicodedata.normalize("NFC", self.tool))
        object.__setattr__(self, "arguments", FrozenDict(values))

    def plain_arguments(self) -> dict[str, Any]:
        return {k: v.data for k, v in self.arguments.items()}


def action_fingerprint(action: PlannedAction) -> str:
    """Return a canonical fingerprint for one exact proposed action.

    Approval tokens bind to the tool *and* complete plain argument set. This
    prevents approval for one payment/email from silently authorizing a later
    action that merely uses the same tool name.
    """

    payload = {"tool": action.tool, "arguments": action.plain_arguments()}
    canonical = canonical_json(payload)
    return hashlib.sha256(canonical).hexdigest()


def deep_freeze(value: Any) -> Any:
    """Copy JSON-like security data into recursively immutable containers."""
    if value is None or isinstance(value, (bool, int, str)):
        return unicodedata.normalize("NFC", value) if isinstance(value, str) else value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not security values")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("security mapping keys must be strings")
            key = unicodedata.normalize("NFC", key)
            if key in frozen:
                raise ValueError("Unicode normalization produced a duplicate key")
            frozen[key] = deep_freeze(item)
        return FrozenDict(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze(item) for item in value)
    raise ValueError(f"unsupported security value type: {type(value).__name__}")


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def canonical_json(value: Any) -> bytes:
    """Canonical UTF-8 JSON with NFC strings, strict types and finite numbers."""
    try:
        frozen = deep_freeze(value)
        return json.dumps(_json_value(frozen), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not canonical security JSON") from exc


def security_equal(left: Any, right: Any) -> bool:
    """Type-sensitive equality for authorization decisions (so True != 1)."""
    try:
        return canonical_json(left) == canonical_json(right)
    except ValueError:
        return False


@dataclass(frozen=True)
class TaskContract:
    """Immutable authorization derived only from trusted input.

    ``bound_arguments`` maps (tool, argument) to the exact trusted value that is
    authorized for this task. ``granted_scopes`` is a capability set such as
    ``{"email:send", "documents:read"}``. Approval binds to an exact action
    fingerprint, not a tool name. None of these can be expanded by model output
    or untrusted data.
    """

    allowed_tools: frozenset[str] | set[str]
    bound_arguments: Mapping[tuple[str, str], TrustedValue] = field(default_factory=dict)
    approved_action_fingerprints: frozenset[str] | set[str] = field(default_factory=frozenset)
    granted_scopes: frozenset[str] | set[str] = field(default_factory=frozenset)
    principal_id: str = "legacy"
    session_id: str = "legacy"
    tenant_id: str = "legacy"
    capability_id: str = "legacy"

    def __post_init__(self) -> None:
        allowed_tools = frozenset(self.allowed_tools)
        scopes = frozenset(self.granted_scopes)
        approvals = frozenset(self.approved_action_fingerprints)
        bindings = dict(self.bound_arguments)
        for label in ("principal_id", "session_id", "tenant_id", "capability_id"):
            value = getattr(self, label)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} must be a non-empty string")

        if any(not isinstance(tool, str) or not tool.strip() for tool in allowed_tools):
            raise ValueError("allowed_tools must contain non-empty strings")
        if any(not isinstance(scope, str) or not scope.strip() for scope in scopes):
            raise ValueError("granted_scopes must contain non-empty strings")
        for key, value in bindings.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or any(not isinstance(part, str) or not part.strip() for part in key)
            ):
                raise ValueError("bound argument keys must be (tool, argument) string tuples")
            if not isinstance(value, Value) or not value.is_trusted:
                raise ValueError("task-contract bindings must contain trusted Values")

        object.__setattr__(self, "allowed_tools", allowed_tools)
        object.__setattr__(self, "granted_scopes", scopes)
        object.__setattr__(self, "approved_action_fingerprints", approvals)
        object.__setattr__(self, "bound_arguments", FrozenDict(bindings))

    def with_approved_action(self, action: PlannedAction) -> "TaskContract":
        fingerprint = action_fingerprint(action)
        return replace(
            self,
            approved_action_fingerprints=self.approved_action_fingerprints | {fingerprint},
        )


class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Decision:
    type: DecisionType
    reasons: tuple[str, ...] = ()
class FrozenDict(dict):
    """A JSON-compatible dictionary that rejects mutation."""
    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("security mapping is immutable")
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _immutable

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenDict":
        return self
