from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import math
import unicodedata
from .models import FrozenDict

import yaml

from .exceptions import PolicyValidationError
from .models import ConfidentialityLevel


@dataclass(frozen=True)
class ArgumentPolicy:
    trust_required: str | None = None
    max_confidentiality: ConfidentialityLevel | None = None


@dataclass(frozen=True)
class ApprovalPolicy:
    field: str
    greater_than: float


@dataclass(frozen=True)
class ToolPolicy:
    allow: bool = False
    arguments: dict[str, ArgumentPolicy] = field(default_factory=dict)
    approval: ApprovalPolicy | None = None
    required_scope: str | None = None
    exact_approval_required: bool = False
    reject_undeclared_arguments: bool = False
    # How many times this tool may be allowed in one session. Enforced only when the
    # reference monitor is given a SessionLedger; without one, a tool that declares a
    # limit is denied rather than allowed without it.
    max_calls: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", FrozenDict(self.arguments))
        if self.max_calls is not None and (
            isinstance(self.max_calls, bool) or not isinstance(self.max_calls, int) or self.max_calls < 0
        ):
            raise ValueError("max_calls must be a non-negative integer")


@dataclass(frozen=True)
class Policy:
    default_action: str = "deny"
    tools: dict[str, ToolPolicy] = field(default_factory=dict)
    version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", FrozenDict(self.tools))


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


def _strict_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        _fail(path, "must be true or false (YAML boolean, not a quoted string)")
    return value


def _non_empty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(path, "must be a non-empty string")
    return unicodedata.normalize("NFC", value)


def _confidentiality(value: Any, path: str) -> ConfidentialityLevel | None:
    if value is None:
        return None
    try:
        return ConfidentialityLevel(value)
    except (TypeError, ValueError):
        allowed = ", ".join(level.value for level in ConfidentialityLevel)
        _fail(path, f"must be one of: {allowed}")
    raise AssertionError("unreachable")


def _parse_argument(raw: Any, path: str, version: int) -> ArgumentPolicy:
    raw = _mapping(raw, path)
    allowed_fields = {"trust_required"}
    if version >= 2:
        allowed_fields.add("max_confidentiality")
    _known_keys(raw, allowed_fields, path)

    trust_required = raw.get("trust_required")
    # Compared by equality, not set membership: `trust_required: {}` is unhashable and
    # made the old `not in {None, "trusted"}` raise TypeError (FIND-053), the same
    # class as FIND-047 one field over.
    if trust_required is not None and trust_required != "trusted":
        _fail(f"{path}.trust_required", "supported value is 'trusted'")

    max_confidentiality = None
    if version >= 2:
        max_confidentiality = _confidentiality(
            raw.get("max_confidentiality"), f"{path}.max_confidentiality"
        )

    return ArgumentPolicy(
        trust_required=trust_required,
        max_confidentiality=max_confidentiality,
    )


def _parse_approval(raw: Any, path: str) -> ApprovalPolicy:
    raw = _mapping(raw, path)
    _known_keys(raw, {"field", "greater_than"}, path)

    field_name = _non_empty_string(raw.get("field"), f"{path}.field")

    threshold = raw.get("greater_than")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        _fail(f"{path}.greater_than", "must be a number")
    if not math.isfinite(float(threshold)):
        _fail(f"{path}.greater_than", "must be finite")

    return ApprovalPolicy(field=field_name, greater_than=float(threshold))


def _parse_tool(raw: Any, path: str, version: int) -> ToolPolicy:
    raw = _mapping(raw, path)
    allowed_fields = {"allow", "arguments", "approval"}
    if version >= 2:
        allowed_fields.add("required_scope")
    if version >= 3:
        allowed_fields.add("exact_approval_required")
    if version >= 4:
        allowed_fields.add("reject_undeclared_arguments")
    if version >= 5:
        allowed_fields.add("max_calls")
    _known_keys(raw, allowed_fields, path)

    allow = _strict_bool(raw.get("allow", False), f"{path}.allow")

    required_scope = None
    if version >= 2 and "required_scope" in raw:
        required_scope = _non_empty_string(
            raw["required_scope"], f"{path}.required_scope"
        )

    arguments_raw = _mapping(raw.get("arguments", {}), f"{path}.arguments")
    arguments: dict[str, ArgumentPolicy] = {}
    for name, cfg in arguments_raw.items():
        normalized_name = _non_empty_string(name, f"{path}.arguments.<argument>")
        if normalized_name in arguments:
            _fail(f"{path}.arguments", "Unicode normalization produced a duplicate argument")
        arguments[normalized_name] = _parse_argument(
            cfg, f"{path}.arguments.{normalized_name}", version
        )

    approval = None
    if "approval" in raw:
        approval = _parse_approval(raw["approval"], f"{path}.approval")
        if approval.field not in arguments and (arguments or version >= 4):
            _fail(
                f"{path}.approval.field",
                f"'{approval.field}' is not declared under {path}.arguments",
            )

    exact_approval_required = False
    if version >= 3 and "exact_approval_required" in raw:
        exact_approval_required = _strict_bool(
            raw["exact_approval_required"], f"{path}.exact_approval_required"
        )

    reject_undeclared_arguments = version >= 4
    if version >= 4 and "reject_undeclared_arguments" in raw:
        reject_undeclared_arguments = _strict_bool(
            raw["reject_undeclared_arguments"], f"{path}.reject_undeclared_arguments")
        if not reject_undeclared_arguments:
            _fail(
                f"{path}.reject_undeclared_arguments",
                "policy v4 requires fail-closed undeclared-argument rejection",
            )

    max_calls = None
    if version >= 5 and "max_calls" in raw:
        max_calls = raw["max_calls"]
        # bool is an int in Python, and a fractional limit would make the comparison
        # depend on rounding. The same rule as max_effect_count (DEC-035).
        if isinstance(max_calls, bool) or not isinstance(max_calls, int):
            _fail(f"{path}.max_calls", "must be an integer")
        if max_calls < 0:
            _fail(f"{path}.max_calls", "must not be negative")

    return ToolPolicy(
        allow=allow,
        arguments=arguments,
        approval=approval,
        required_scope=required_scope,
        exact_approval_required=exact_approval_required,
        reject_undeclared_arguments=reject_undeclared_arguments,
        max_calls=max_calls,
    )


def load_policy(path: str | Path) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    raw = _mapping(raw, "policy")
    _known_keys(raw, {"version", "default_action", "tools"}, "policy")

    version = raw.get("version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version not in {1, 2, 3, 4, 5}:
        _fail("policy.version", "supported versions are 1, 2, 3, 4 and 5")

    default_action = raw.get("default_action", "deny")
    # The isinstance guard is load-bearing, not decoration. Set membership raises
    # TypeError for an unhashable operand, so `default_action: [allow, deny]`
    # reached this line and failed with "unhashable type: 'list'" rather than a
    # PolicyValidationError. The version check above already has this shape and
    # short-circuits correctly; this one did not (FIND-047).
    if not isinstance(default_action, str) or default_action not in {"allow", "deny"}:
        _fail("policy.default_action", "must be 'allow' or 'deny'")
    if version >= 4 and default_action != "deny":
        _fail("policy.default_action", "policy v4 requires fail-closed 'deny'")

    tools_raw = _mapping(raw.get("tools", {}), "policy.tools")
    tools: dict[str, ToolPolicy] = {}
    for name, cfg in tools_raw.items():
        normalized_name = _non_empty_string(name, "policy.tools.<tool>")
        if normalized_name in tools:
            _fail("policy.tools", "Unicode normalization produced a duplicate tool")
        tools[normalized_name] = _parse_tool(
            cfg, f"policy.tools.{normalized_name}", version
        )

    return Policy(default_action=default_action, tools=tools, version=version)
