from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import math
import unicodedata

import yaml

from .exceptions import PolicyValidationError
from .models import ConfidentialityLevel, TaskContract, security_equal
from .sandbox import Effect


@dataclass(frozen=True)
class InvariantDefinition:
    id: str
    description: str
    type: str
    effect: str
    field: str | None = None
    binding: tuple[str, str] | None = None
    max_confidentiality: ConfidentialityLevel | None = None
    forbidden_values: tuple[str, ...] = ()
    greater_than: float | None = None


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    effect_index: int
    reason: str


class DeclarativeInvariantEngine:
    """Evaluate declarative security invariants over observable effects."""

    def __init__(self, invariants: list[InvariantDefinition]) -> None:
        ids = [item.id for item in invariants]
        if len(ids) != len(set(ids)):
            raise ValueError("security invariant IDs must be unique")
        self.invariants = tuple(invariants)

    def evaluate(
        self,
        effects: list[Effect],
        contract: TaskContract,
    ) -> tuple[InvariantViolation, ...]:
        violations: list[InvariantViolation] = []
        for invariant in self.invariants:
            for index, effect in enumerate(effects):
                if effect.kind != invariant.effect:
                    continue
                reason = self._violation_reason(invariant, effect, contract)
                if reason:
                    violations.append(
                        InvariantViolation(
                            invariant_id=invariant.id,
                            effect_index=index,
                            reason=reason,
                        )
                    )
        return tuple(violations)

    @staticmethod
    def _violation_reason(
        invariant: InvariantDefinition,
        effect: Effect,
        contract: TaskContract,
    ) -> str | None:
        if invariant.type == "forbidden_effect":
            return f"forbidden_effect:{effect.kind}"

        if invariant.type == "contract_binding":
            assert invariant.field is not None
            assert invariant.binding is not None
            trusted = contract.bound_arguments.get(invariant.binding)
            if trusted is None:
                return f"missing_contract_binding:{invariant.binding[0]}.{invariant.binding[1]}"
            actual = effect.attributes.get(invariant.field)
            if not security_equal(actual, trusted.data):
                return f"field_differs_from_binding:{invariant.field}"
            return None

        if invariant.type == "confidentiality_ceiling":
            assert invariant.field is not None
            assert invariant.max_confidentiality is not None
            provenance = effect.provenance.get(invariant.field)
            if provenance is None:
                return f"missing_effect_provenance:{invariant.field}"
            if provenance.confidentiality.rank > invariant.max_confidentiality.rank:
                return (
                    f"confidentiality_exceeds_limit:{invariant.field}:"
                    f"{provenance.confidentiality.value}>{invariant.max_confidentiality.value}"
                )
            return None

        if invariant.type == "forbidden_values":
            assert invariant.field is not None
            actual = effect.attributes.get(invariant.field)
            if actual is None:
                return None
            text = str(actual)
            for forbidden in invariant.forbidden_values:
                if forbidden in text:
                    return f"forbidden_value_observed:{invariant.field}"
            return None

        if invariant.type == "exact_action_approval":
            assert invariant.field is not None
            assert invariant.greater_than is not None
            actual = effect.attributes.get(invariant.field)
            if actual is None:
                return f"missing_approval_field:{invariant.field}"
            try:
                numeric = float(actual)
                if isinstance(actual, bool) or not math.isfinite(numeric):
                    raise ValueError
                exceeds = numeric > invariant.greater_than
            except (TypeError, ValueError):
                return f"invalid_numeric_field:{invariant.field}"
            if not exceeds:
                return None
            if effect.action_fingerprint is None:
                return "missing_effect_action_fingerprint"
            if effect.action_fingerprint not in contract.approved_action_fingerprints:
                return "effect_not_exactly_approved"
            return None

        raise AssertionError(f"unsupported invariant type: {invariant.type}")


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


def _non_empty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(path, "must be a non-empty string")
    return unicodedata.normalize("NFC", value)


def _parse_binding(value: Any, path: str) -> tuple[str, str]:
    text = _non_empty_string(value, path)
    parts = text.split(".", 1)
    if len(parts) != 2 or not all(parts):
        _fail(path, "must use 'tool.argument' syntax")
    return parts[0], parts[1]


def _parse_invariant(raw: Any, path: str) -> InvariantDefinition:
    raw = _mapping(raw, path)
    _known_keys(
        raw,
        {
            "id",
            "description",
            "type",
            "effect",
            "field",
            "binding",
            "max_confidentiality",
            "forbidden_values",
            "greater_than",
        },
        path,
    )

    invariant_id = _non_empty_string(raw.get("id"), f"{path}.id")
    description = _non_empty_string(raw.get("description", invariant_id), f"{path}.description")
    invariant_type = _non_empty_string(raw.get("type"), f"{path}.type")
    effect = _non_empty_string(raw.get("effect"), f"{path}.effect")

    supported = {
        "forbidden_effect",
        "contract_binding",
        "confidentiality_ceiling",
        "forbidden_values",
        "exact_action_approval",
    }
    if invariant_type not in supported:
        _fail(f"{path}.type", f"supported values are: {', '.join(sorted(supported))}")

    field = None
    binding = None
    max_confidentiality = None
    forbidden_values: tuple[str, ...] = ()
    greater_than: float | None = None

    if invariant_type in {"contract_binding", "confidentiality_ceiling", "forbidden_values", "exact_action_approval"}:
        field = _non_empty_string(raw.get("field"), f"{path}.field")

    if invariant_type == "contract_binding":
        binding = _parse_binding(raw.get("binding"), f"{path}.binding")

    if invariant_type == "confidentiality_ceiling":
        raw_level = raw.get("max_confidentiality")
        try:
            max_confidentiality = ConfidentialityLevel(raw_level)
        except (TypeError, ValueError):
            allowed = ", ".join(level.value for level in ConfidentialityLevel)
            _fail(f"{path}.max_confidentiality", f"must be one of: {allowed}")

    if invariant_type == "forbidden_values":
        raw_values = raw.get("forbidden_values")
        if not isinstance(raw_values, list) or not raw_values:
            _fail(f"{path}.forbidden_values", "must be a non-empty list of strings")
        parsed: list[str] = []
        for index, value in enumerate(raw_values):
            parsed.append(_non_empty_string(value, f"{path}.forbidden_values[{index}]"))
        forbidden_values = tuple(parsed)

    if invariant_type == "exact_action_approval":
        raw_threshold = raw.get("greater_than")
        if isinstance(raw_threshold, bool) or not isinstance(raw_threshold, (int, float)):
            _fail(f"{path}.greater_than", "must be a number")
        greater_than = float(raw_threshold)
        if not math.isfinite(greater_than):
            _fail(f"{path}.greater_than", "must be finite")

    return InvariantDefinition(
        id=invariant_id,
        description=description,
        type=invariant_type,
        effect=effect,
        field=field,
        binding=binding,
        max_confidentiality=max_confidentiality,
        forbidden_values=forbidden_values,
        greater_than=greater_than,
    )


def load_invariants(path: str | Path) -> DeclarativeInvariantEngine:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    raw = _mapping(raw, "invariants")
    _known_keys(raw, {"version", "invariants"}, "invariants")
    version = raw.get("version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        _fail("invariants.version", "only version 1 is supported")

    items = raw.get("invariants", [])
    if not isinstance(items, list):
        _fail("invariants.invariants", "must be a list")
    if not items:
        _fail("invariants.invariants", "must contain at least one invariant")

    definitions = [
        _parse_invariant(item, f"invariants.invariants[{index}]")
        for index, item in enumerate(items)
    ]
    try:
        return DeclarativeInvariantEngine(definitions)
    except ValueError as exc:
        _fail("invariants.invariants", str(exc))
    raise AssertionError("unreachable")
