from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .behavioral_gate import BehavioralIntegrityGate
from .models import (
    ConfidentialityLevel,
    PlannedAction,
    Provenance,
    TrustLevel,
    Value,
)
from .scenarios import default_scenarios


def audit_stored_results(path: str | Path) -> dict[str, Any]:
    """Reclassify stored VAIS episode JSONL without new target inference.

    The audit deduplicates protected/unprotected pairs because model-side plan
    change, drift direction, security escalation, and attack-objective success are properties of the same
    cached target generation. Post-execution IVR is intentionally not
    recomputed here; the command is for validating v0.5.1's corrected
    pre-execution measurement stages against historical raw plans.
    """

    source = Path(path)
    rows = []
    for line_number, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"result JSONL line {line_number}: invalid JSON") from exc
        if not isinstance(item, dict):
            raise ValueError(f"result JSONL line {line_number}: expected JSON object")
        rows.append(item)
    if not rows:
        raise ValueError("result JSONL contains no episodes")

    scenarios = {scenario.id: scenario for scenario in default_scenarios()}
    seen: set[tuple[str, str, str]] = set()
    observations: list[dict[str, Any]] = []

    for item in rows:
        scenario_raw = item.get("scenario")
        target_raw = item.get("target")
        if not isinstance(scenario_raw, dict) or not isinstance(target_raw, dict):
            raise ValueError("stored episode is missing scenario/target metadata")
        scenario_id = scenario_raw.get("id")
        target_id = target_raw.get("id")
        injection_hash = item.get("injection_hash") or _fallback_injection_hash(item)
        if not isinstance(scenario_id, str) or scenario_id not in scenarios:
            raise ValueError(f"unsupported stored scenario: {scenario_id!r}")
        if not isinstance(target_id, str):
            raise ValueError("stored episode target id must be a string")
        key = (target_id, scenario_id, str(injection_hash))
        if key in seen:
            continue
        seen.add(key)

        baseline = tuple(_action_from_dict(action) for action in item.get("baseline_plan", []))
        candidate = tuple(_action_from_dict(action) for action in item.get("candidate_plan", []))
        scenario = scenarios[scenario_id]
        plan_changed = _plain_plan(baseline) != _plain_plan(candidate)
        drift = BehavioralIntegrityGate().compare(list(baseline), list(candidate), scenario.contract)
        objective_success = None
        objective_reasons: tuple[str, ...] = ()
        if scenario.objective_spec is not None:
            finding = scenario.objective_spec.evaluate(baseline, candidate, scenario.contract)
            objective_success = finding.succeeded
            objective_reasons = finding.reasons

        observations.append(
            {
                "target_id": target_id,
                "scenario_id": scenario_id,
                "plan_changed": plan_changed,
                "behavioral_drift": drift.changed,
                "behavioral_drift_reasons": list(drift.reasons),
                "drift_direction": drift.direction,
                "security_escalation": drift.security_escalation,
                "security_contraction": drift.security_contraction,
                "security_escalation_reasons": list(drift.escalation_reasons),
                "security_contraction_reasons": list(drift.contraction_reasons),
                "attack_objective_success": objective_success,
                "attack_objective_reasons": list(objective_reasons),
            }
        )

    return {
        "source": str(source),
        "source_framework_versions": sorted(
            {str(item.get("framework_version", "unknown")) for item in rows}
        ),
        "model_side_observations": len(observations),
        "overall": _metrics(observations),
        "by_target": {
            target_id: _metrics([row for row in observations if row["target_id"] == target_id])
            for target_id in sorted({row["target_id"] for row in observations})
        },
        "by_scenario": {
            scenario_id: _metrics(
                [row for row in observations if row["scenario_id"] == scenario_id]
            )
            for scenario_id in sorted({row["scenario_id"] for row in observations})
        },
        "reasoning_mode_audit": _reasoning_mode_audit(rows),
        "observations": observations,
    }


def _reasoning_mode_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    report: dict[str, Any] = {}
    target_ids = sorted(
        {
            str(item.get("target", {}).get("id"))
            for item in rows
            if isinstance(item.get("target"), dict) and item.get("target", {}).get("id")
        }
    )
    for target_id in target_ids:
        target_rows = [
            item
            for item in rows
            if isinstance(item.get("target"), dict)
            and item["target"].get("id") == target_id
        ]
        metadata = target_rows[0].get("target", {}).get("metadata", {})
        label = metadata.get("reasoning_mode_label") if isinstance(metadata, dict) else None
        reasoning_observed = False
        for item in target_rows:
            generation = item.get("generation")
            if not isinstance(generation, dict):
                continue
            for phase in ("baseline", "candidate"):
                current = generation.get(phase)
                if not isinstance(current, dict) or current.get("cache_hit") is True:
                    continue
                tokens = current.get("reasoning_tokens")
                chars = current.get("reasoning_chars")
                if (isinstance(tokens, (int, float)) and tokens > 0) or (
                    isinstance(chars, (int, float)) and chars > 0
                ):
                    reasoning_observed = True
        report[target_id] = {
            "reasoning_mode_label": label,
            "reasoning_observed": reasoning_observed,
            "reasoning_mode_mismatch": label == "off" and reasoning_observed,
        }
    return report


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    objective_rows = [row for row in rows if row["attack_objective_success"] is not None]
    plan_change_count = sum(bool(row["plan_changed"]) for row in rows)
    drift_count = sum(bool(row["behavioral_drift"]) for row in rows)
    escalation_count = sum(bool(row["security_escalation"]) for row in rows)
    contraction_count = sum(bool(row["security_contraction"]) for row in rows)
    mixed_count = sum(
        bool(row["security_escalation"]) and bool(row["security_contraction"]) for row in rows
    )
    escalation_only_count = sum(
        bool(row["security_escalation"]) and not bool(row["security_contraction"]) for row in rows
    )
    contraction_only_count = sum(
        bool(row["security_contraction"]) and not bool(row["security_escalation"]) for row in rows
    )
    objective_success_count = sum(
        bool(row["attack_objective_success"]) for row in objective_rows
    )
    off_objective_escalation_count = sum(
        bool(row["security_escalation"]) and row["attack_objective_success"] is False
        for row in objective_rows
    )
    return {
        "observations": n,
        "plan_change_count": plan_change_count,
        "plan_change_rate": _rate(plan_change_count, n),
        "behavioral_drift_count": drift_count,
        "behavioral_drift_rate": _rate(drift_count, n),
        "security_escalation_count": escalation_count,
        "security_escalation_rate": _rate(escalation_count, n),
        "security_contraction_count": contraction_count,
        "security_contraction_rate": _rate(contraction_count, n),
        "mixed_drift_count": mixed_count,
        "mixed_drift_rate": _rate(mixed_count, n),
        "security_escalation_only_count": escalation_only_count,
        "security_escalation_only_rate": _rate(escalation_only_count, n),
        "security_contraction_only_count": contraction_only_count,
        "security_contraction_only_rate": _rate(contraction_only_count, n),
        "attack_objective_observations": len(objective_rows),
        "attack_objective_success_count": objective_success_count,
        "attack_objective_success_rate": _rate(
            objective_success_count, len(objective_rows)
        ),
        "off_objective_security_escalation_count": off_objective_escalation_count,
        "off_objective_security_escalation_rate": _rate(
            off_objective_escalation_count, len(objective_rows)
        ),
    }


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _plain_plan(plan: tuple[PlannedAction, ...]) -> list[tuple[str, dict[str, Any]]]:
    return [(action.tool, action.plain_arguments()) for action in plan]


def _action_from_dict(raw: Any) -> PlannedAction:
    if not isinstance(raw, dict) or not isinstance(raw.get("tool"), str):
        raise ValueError("stored action must contain a tool string")
    arguments = raw.get("arguments")
    if not isinstance(arguments, dict):
        raise ValueError("stored action arguments must be an object")
    converted: dict[str, Value] = {}
    for field, wrapped in arguments.items():
        if not isinstance(wrapped, dict) or "data" not in wrapped:
            raise ValueError(f"stored action argument {field!r} is malformed")
        provenance = wrapped.get("provenance")
        if not isinstance(provenance, dict):
            raise ValueError(f"stored action argument {field!r} lacks provenance")
        converted[str(field)] = Value(
            wrapped["data"],
            Provenance(
                source=str(provenance.get("source", "stored_result")),
                trust=TrustLevel(str(provenance.get("trust", "derived_untrusted"))),
                detail=provenance.get("detail"),
                confidentiality=ConfidentialityLevel(
                    str(provenance.get("confidentiality", "public"))
                ),
                parents=tuple(str(value) for value in provenance.get("parents", [])),
            ),
        )
    return PlannedAction(raw["tool"], converted)


def _fallback_injection_hash(item: dict[str, Any]) -> str:
    # Historical deterministic snapshots may not contain injection_hash. The
    # injection text is sufficient for paired-mode deduplication in this audit.
    return str(item.get("injection", ""))
