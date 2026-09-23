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

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("provenance source must be a non-empty string")
        if not isinstance(self.trust, TrustLevel):
            raise ValueError("provenance trust must be a TrustLevel")
        if not isinstance(self.confidentiality, ConfidentialityLevel):
            raise ValueError("provenance confidentiality must be a ConfidentialityLevel")
        if self.detail is not None and not isinstance(self.detail, str):
            raise ValueError("provenance detail must be a string or None")
        parents = tuple(self.parents)
        if any(not isinstance(parent, str) or not parent.strip() for parent in parents):
            raise ValueError("provenance parents must contain non-empty strings")
        object.__setattr__(self, "source", unicodedata.normalize("NFC", self.source))
        if self.detail is not None:
            object.__setattr__(self, "detail", unicodedata.normalize("NFC", self.detail))
        object.__setattr__(
            self,
            "parents",
            tuple(unicodedata.normalize("NFC", parent) for parent in parents),
        )


@dataclass(frozen=True)
class Value:
    data: Any
    provenance: Provenance

    def __post_init__(self) -> None:
        if not isinstance(self.provenance, Provenance):
            raise ValueError("security value provenance must be Provenance")
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
        values: dict[str, Value] = {}
        for key, value in self.arguments.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("argument names must be non-empty strings")
            normalized = unicodedata.normalize("NFC", key)
            if normalized in values:
                raise ValueError("Unicode normalization produced a duplicate argument name")
            if not isinstance(value, Value):
                raise ValueError("action arguments must be Values")
            values[normalized] = value
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


# Maximum container-nesting depth accepted for any security value. Chosen well
# below the interpreter's default recursion limit (1000) so that pathological
# nesting is rejected as a ValueError *before* it can raise RecursionError.
# RecursionError is not a ValueError, so it would otherwise bypass the
# ``except ValueError`` guards in the reference monitor (the
# ``action_not_fingerprintable`` DENY path) and yield no decision and no audit
# record. No legitimate security value nests anywhere near this deep.
MAX_SECURITY_DEPTH = 256


def deep_freeze(value: Any, _depth: int = 0) -> Any:
    """Copy JSON-like security data into recursively immutable containers.

    Recursion is bounded at ``MAX_SECURITY_DEPTH``: deeper structures raise
    ``ValueError`` (never ``RecursionError``) so the failure routes through the
    normal fail-closed canonicalization path.
    """
    if _depth > MAX_SECURITY_DEPTH:
        raise ValueError(f"security value nesting exceeds maximum depth {MAX_SECURITY_DEPTH}")
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
            frozen[key] = deep_freeze(item, _depth + 1)
        return FrozenDict(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze(item, _depth + 1) for item in value)
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

    ``not_before`` and ``not_after`` bound when the contract's authority holds, as
    seconds since the epoch; the reference monitor denies outside the window. A
    contract without them is valid for as long as it is used (LIM-047). ``delegate``
    derives a narrower contract for a sub-agent and cannot widen anything.
    """

    allowed_tools: frozenset[str] | set[str]
    bound_arguments: Mapping[tuple[str, str], TrustedValue] = field(default_factory=dict)
    approved_action_fingerprints: frozenset[str] | set[str] = field(default_factory=frozenset)
    granted_scopes: frozenset[str] | set[str] = field(default_factory=frozenset)
    principal_id: str = "legacy"
    session_id: str = "legacy"
    tenant_id: str = "legacy"
    capability_id: str = "legacy"
    not_before: float | None = None
    not_after: float | None = None

    def __post_init__(self) -> None:
        raw_tools = tuple(self.allowed_tools)
        raw_scopes = tuple(self.granted_scopes)
        raw_approvals = tuple(self.approved_action_fingerprints)
        if any(not isinstance(tool, str) or not tool.strip() for tool in raw_tools):
            raise ValueError("allowed_tools must contain non-empty strings")
        if any(not isinstance(scope, str) or not scope.strip() for scope in raw_scopes):
            raise ValueError("granted_scopes must contain non-empty strings")
        if any(not isinstance(item, str) or not item.strip() for item in raw_approvals):
            raise ValueError("approved action fingerprints must contain non-empty strings")
        allowed_tools = frozenset(unicodedata.normalize("NFC", tool) for tool in raw_tools)
        scopes = frozenset(unicodedata.normalize("NFC", scope) for scope in raw_scopes)
        approvals = frozenset(unicodedata.normalize("NFC", item) for item in raw_approvals)
        if len(allowed_tools) != len(raw_tools):
            raise ValueError("Unicode normalization produced duplicate allowed tools")
        if len(scopes) != len(raw_scopes):
            raise ValueError("Unicode normalization produced duplicate granted scopes")
        bindings: dict[tuple[str, str], TrustedValue] = {}
        for label in ("principal_id", "session_id", "tenant_id", "capability_id"):
            value = getattr(self, label)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} must be a non-empty string")
            object.__setattr__(self, label, unicodedata.normalize("NFC", value))

        for label in ("not_before", "not_after"):
            value = getattr(self, label)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
            ):
                raise ValueError(f"{label} must be a finite number of seconds or None")
        if self.not_before is not None and self.not_after is not None and self.not_before >= self.not_after:
            raise ValueError("not_before must be earlier than not_after")

        for key, value in self.bound_arguments.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or any(not isinstance(part, str) or not part.strip() for part in key)
            ):
                raise ValueError("bound argument keys must be (tool, argument) string tuples")
            if not isinstance(value, Value) or not value.is_trusted:
                raise ValueError("task-contract bindings must contain trusted Values")
            normalized_key = tuple(unicodedata.normalize("NFC", part) for part in key)
            if normalized_key in bindings:
                raise ValueError("Unicode normalization produced a duplicate contract binding")
            bindings[normalized_key] = value

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

    def delegate(
        self,
        *,
        capability_id: str,
        allowed_tools: frozenset[str] | set[str] | None = None,
        granted_scopes: frozenset[str] | set[str] | None = None,
        approved_action_fingerprints: frozenset[str] | set[str] | None = None,
        not_after: float | None = None,
    ) -> "TaskContract":
        """Derive the contract for a sub-agent, which may only narrow this one.

        Tools, scopes and approvals must each be a subset of this contract's, bindings
        are inherited unchanged for the tools kept, and the validity window can only
        shrink. Anything wider raises ``ValueError`` rather than being trimmed, so a
        delegation that asks for more than the parent holds is a visible error.

        The delegate keeps this contract's principal, session and tenant and takes a new
        capability id. Keeping the session is what makes delegation attenuating in
        practice: a ``SessionLedger`` is keyed by session, so a delegate's calls count
        against the parent's limits and its use of a contract-held approval spends the
        parent's, and revoking the session revokes every delegate in it.
        """
        child = TaskContract(
            allowed_tools=self.allowed_tools if allowed_tools is None else allowed_tools,
            bound_arguments={},
            approved_action_fingerprints=(
                self.approved_action_fingerprints if approved_action_fingerprints is None
                else approved_action_fingerprints
            ),
            granted_scopes=self.granted_scopes if granted_scopes is None else granted_scopes,
            principal_id=self.principal_id,
            session_id=self.session_id,
            tenant_id=self.tenant_id,
            capability_id=capability_id,
            not_before=self.not_before,
            not_after=self.not_after if not_after is None else not_after,
        )
        if child.capability_id == self.capability_id:
            raise ValueError("a delegate needs its own capability_id")
        if not child.allowed_tools <= self.allowed_tools:
            raise ValueError("delegation cannot add tools")
        if not child.granted_scopes <= self.granted_scopes:
            raise ValueError("delegation cannot add scopes")
        if not child.approved_action_fingerprints <= self.approved_action_fingerprints:
            raise ValueError("delegation cannot add approvals")
        if self.not_after is not None and child.not_after > self.not_after:
            raise ValueError("delegation cannot extend the validity window")
        bindings = {key: value for key, value in self.bound_arguments.items() if key[0] in child.allowed_tools}
        return replace(child, bound_arguments=bindings)


class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Decision:
    type: DecisionType
    reasons: tuple[str, ...] = ()
class FrozenDict(dict):
    """A JSON-compatible dictionary that rejects mutation.

    Every in-place mutator ``dict`` defines is blocked, including ``|=``. That one
    was missed until rc12 (FIND-052): ``dict.__ior__`` is implemented in C and does
    not route through ``update``, so ``contract.bound_arguments |= {...}`` rewrote a
    trusted binding. What Python cannot block is a deliberate unbound call such as
    ``dict.update(mapping, ...)``; this guards against accidents, not hostile code
    running in-process, which the threat model already excludes.
    """
    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("security mapping is immutable")
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _immutable
    __ior__ = _immutable

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenDict":
        return self
