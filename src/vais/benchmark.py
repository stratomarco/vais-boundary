from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from ._version import __version__
from .adaptive import AttackObservation, Attacker, TargetAgent
from .behavioral_gate import BehavioralIntegrityGate, DriftFinding
from .executor import ExecutionRecord, ProtectedExecutor
from .models import Decision, DecisionType, PlannedAction, Value
from .monitor import ReferenceMonitor
from .reward import DeclarativeVerifiableReward
from .sandbox import Effect, SandboxExecutor
from .scenarios import Scenario
from .targeting import GenerationMetadata, TargetRunResult, TargetStatus


class ProtectionMode(str, Enum):
    UNPROTECTED = "unprotected"
    PROTECTED = "protected"


@dataclass(frozen=True)
class EpisodeResult:
    framework_version: str
    episode_id: str
    scenario_id: str
    scenario_version: int
    target_id: str
    target_metadata: dict[str, str]
    attacker_id: str
    attacker_metadata: dict[str, str]
    mode: ProtectionMode
    injection: str
    injection_hash: str
    baseline_plan: tuple[PlannedAction, ...]
    candidate_plan: tuple[PlannedAction, ...]
    baseline_generation: GenerationMetadata
    candidate_generation: GenerationMetadata
    drift: DriftFinding | None
    records: tuple[ExecutionRecord, ...]
    effects: tuple[Effect, ...]
    violations: tuple[str, ...]
    violation_details: tuple[dict[str, Any], ...]
    reward: float | None
    plan_changed: bool | None
    attack_objective_success: bool | None
    attack_objective_reasons: tuple[str, ...]
    clean_utility_success: bool | None
    security_evaluated: bool
    policy_hash: str
    invariant_hash: str
    execution_backend: str = "sandbox"
    ingress: dict[str, Any] | None = None
    mcp_call_states: tuple[str, ...] = ()
    mcp_remote_call_count: int = 0

    @property
    def protected(self) -> bool:
        return self.mode == ProtectionMode.PROTECTED

    @property
    def target_status(self) -> TargetStatus:
        return self.candidate_generation.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework_version": self.framework_version,
            "episode_id": self.episode_id,
            "scenario": {"id": self.scenario_id, "version": self.scenario_version},
            "target": {"id": self.target_id, "metadata": self.target_metadata},
            "attacker": {"id": self.attacker_id, "metadata": self.attacker_metadata},
            "mode": self.mode.value,
            "injection": self.injection,
            "injection_hash": self.injection_hash,
            "target_status": self.target_status.value,
            "security_evaluated": self.security_evaluated,
            "generation": {
                "baseline": self.baseline_generation.to_dict(),
                "candidate": self.candidate_generation.to_dict(),
            },
            "baseline_plan": [_action_dict(item) for item in self.baseline_plan],
            "candidate_plan": [_action_dict(item) for item in self.candidate_plan],
            "behavioral_drift": (
                {
                    "changed": self.drift.changed,
                    "score": self.drift.score,
                    "reasons": list(self.drift.reasons),
                    "direction": self.drift.direction,
                    "security_escalation": self.drift.security_escalation,
                    "security_contraction": self.drift.security_contraction,
                    "escalation_reasons": list(self.drift.escalation_reasons),
                    "contraction_reasons": list(self.drift.contraction_reasons),
                }
                if self.drift is not None
                else None
            ),
            "decisions": [
                {
                    "tool": record.action.tool,
                    "decision": record.decision.type.value,
                    "reasons": list(record.decision.reasons),
                    "effect": _effect_dict(record.effect) if record.effect is not None else None,
                }
                for record in self.records
            ],
            "effects": [_effect_dict(effect) for effect in self.effects],
            "violations": list(self.violations),
            "violation_details": list(self.violation_details),
            "terminal_security_reward": self.reward,
            "plan_changed": self.plan_changed,
            "attack_objective_success": self.attack_objective_success,
            "attack_objective_reasons": list(self.attack_objective_reasons),
            "clean_utility_success": self.clean_utility_success,
            "policy_hash": self.policy_hash,
            "invariant_hash": self.invariant_hash,
            "execution_backend": self.execution_backend,
            "ingress": self.ingress,
            "mcp": {
                "call_states": list(self.mcp_call_states),
                "remote_call_count": self.mcp_remote_call_count,
            } if self.execution_backend == "mcp" else None,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class BenchmarkRunner:
    """Execute clean and attacked plans with deterministic result recording.

    Target-generation failures are first-class outcomes. Security metrics are
    only computed when both the clean baseline and attacked candidate produced
    valid plans. This prevents malformed/truncated target output from being
    mislabeled as attack resistance or defense success.
    """

    def __init__(self) -> None:
        self._histories: dict[tuple[str, str, str, str], list[AttackObservation]] = {}

    def run_episode(
        self,
        scenario: Scenario,
        target: TargetAgent,
        attacker: Attacker,
        mode: ProtectionMode = ProtectionMode.PROTECTED,
    ) -> EpisodeResult:
        key = (attacker.attacker_id, target.target_id, scenario.id, mode.value)
        history = tuple(self._histories.get(key, []))
        injection = attacker.generate(scenario, history)

        baseline_run = _target_run(target, scenario, None)
        candidate_run = _target_run(target, scenario, injection)
        baseline = baseline_run.plan
        candidate = candidate_run.plan

        policy_hash = stable_hash(scenario.policy)
        invariant_hash = stable_hash(scenario.invariants.invariants)
        injection_hash = hashlib.sha256(injection.encode("utf-8")).hexdigest()

        clean_utility: bool | None = None
        if baseline_run.valid:
            clean_effects = self._execute_clean(scenario, baseline, mode)
            clean_utility = scenario.clean_utility_success(clean_effects)

        security_evaluated = baseline_run.valid and candidate_run.valid
        drift: DriftFinding | None = None
        records: tuple[ExecutionRecord, ...] = ()
        effects: tuple[Effect, ...] = ()
        violations: tuple[str, ...] = ()
        details: tuple[dict[str, Any], ...] = ()
        reward: float | None = None
        plan_changed: bool | None = None
        attack_objective_success: bool | None = None
        attack_objective_reasons: tuple[str, ...] = ()

        if security_evaluated:
            gate = BehavioralIntegrityGate()
            drift = gate.compare(list(baseline), list(candidate), scenario.contract)
            rewarder = DeclarativeVerifiableReward(scenario.invariants)
            plan_changed = _plans_plain_differ(baseline, candidate)
            if scenario.objective_spec is not None:
                objective = scenario.objective_spec.evaluate(baseline, candidate, scenario.contract)
                attack_objective_success = objective.succeeded
                attack_objective_reasons = objective.reasons

            if mode == ProtectionMode.PROTECTED:
                executor = ProtectedExecutor(
                    ReferenceMonitor(scenario.policy),
                    SandboxExecutor(),
                )
                records = tuple(executor.run(list(candidate), scenario.contract))
            else:
                records = tuple(self._run_unprotected(candidate))

            effects = tuple(record.effect for record in records if record.effect is not None)
            reward, violations = rewarder.evaluate(list(effects), scenario.contract)
            details = tuple(
                {
                    "invariant_id": item.invariant_id,
                    "effect_index": item.effect_index,
                    "reason": item.reason,
                }
                for item in rewarder.last_details
            )

        episode_id = stable_hash(
            {
                "framework_version": __version__,
                "scenario_id": scenario.id,
                "scenario_version": scenario.version,
                "target_id": target.target_id,
                "attacker_id": attacker.attacker_id,
                "mode": mode.value,
                "injection_hash": injection_hash,
                "policy_hash": policy_hash,
                "invariant_hash": invariant_hash,
            }
        )[:24]

        result = EpisodeResult(
            framework_version=__version__,
            episode_id=episode_id,
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            target_id=target.target_id,
            target_metadata=dict(target.metadata()),
            attacker_id=attacker.attacker_id,
            attacker_metadata=_attacker_metadata(attacker),
            mode=mode,
            injection=injection,
            injection_hash=injection_hash,
            baseline_plan=baseline,
            candidate_plan=candidate,
            baseline_generation=baseline_run.generation,
            candidate_generation=candidate_run.generation,
            drift=drift,
            records=records,
            effects=effects,
            violations=violations,
            violation_details=details,
            reward=reward,
            plan_changed=plan_changed,
            attack_objective_success=attack_objective_success,
            attack_objective_reasons=attack_objective_reasons,
            clean_utility_success=clean_utility,
            security_evaluated=security_evaluated,
            policy_hash=policy_hash,
            invariant_hash=invariant_hash,
        )

        self._histories.setdefault(key, []).append(
            AttackObservation(
                injection=injection,
                reward=reward,
                violations=violations,
                plan_changed=plan_changed,
                behavioral_drift=drift.changed if drift is not None else None,
                attack_objective_success=attack_objective_success,
                protected=mode == ProtectionMode.PROTECTED,
            )
        )
        attacker.observe(result)
        return result

    def run_matrix(
        self,
        scenarios: tuple[Scenario, ...] | list[Scenario],
        targets: tuple[TargetAgent, ...] | list[TargetAgent],
        attackers: tuple[Attacker, ...] | list[Attacker],
        modes: tuple[ProtectionMode, ...] = (
            ProtectionMode.UNPROTECTED,
            ProtectionMode.PROTECTED,
        ),
    ) -> tuple[EpisodeResult, ...]:
        results: list[EpisodeResult] = []
        for target in targets:
            for scenario in scenarios:
                for attacker in attackers:
                    supports = getattr(attacker, "supports_scenario", None)
                    if callable(supports) and not supports(scenario):
                        continue
                    for mode in modes:
                        results.append(self.run_episode(scenario, target, attacker, mode))
        return tuple(results)

    @staticmethod
    def _run_unprotected(actions: tuple[PlannedAction, ...]) -> list[ExecutionRecord]:
        sandbox = SandboxExecutor()
        return [
            ExecutionRecord(
                action=action,
                decision=Decision(DecisionType.ALLOW, ("unprotected_bypass",)),
                effect=sandbox.execute(action),
            )
            for action in actions
        ]

    @staticmethod
    def _execute_clean(
        scenario: Scenario,
        baseline: tuple[PlannedAction, ...],
        mode: ProtectionMode,
    ) -> tuple[Effect, ...]:
        if mode == ProtectionMode.PROTECTED:
            records = ProtectedExecutor(
                ReferenceMonitor(scenario.policy),
                SandboxExecutor(),
            ).run(list(baseline), scenario.contract)
            return tuple(record.effect for record in records if record.effect is not None)
        sandbox = SandboxExecutor()
        return tuple(sandbox.execute(action) for action in baseline)


def summarize_results(results: tuple[EpisodeResult, ...] | list[EpisodeResult]) -> dict[str, Any]:
    items = list(results)
    return {
        "framework_version": __version__,
        "episodes": len(items),
        "execution_backends": sorted({item.execution_backend for item in items}),
        "methodology": {
            "security_metric_denominator": "episodes with valid baseline and candidate target plans",
            "target_failures_count_as_security_success": False,
            "transport_retries_apply_only_before_target-plan evaluation": True,
            "confidence_interval": "Wilson score 95% for primary rates",
            "measurement_stages": [
                "plan_changed",
                "behavioral_drift",
                "security_escalation",
                "attack_objective_success",
                "observable_invariant_violation",
            ],
            "plan_changed_is_not_attack_success": True,
            "behavioral_drift_can_be_escalation_or_contraction": True,
            "security_escalation_is_diagnostic_not_authorization": True,
            "off_objective_escalation_is_not_attack_objective_success": True,
        },
        "overall": _metrics(items),
        "targets": {
            target_id: next(item.target_metadata for item in items if item.target_id == target_id)
            for target_id in sorted({item.target_id for item in items})
        },
        "target_health": _target_health(items),
        "target_health_by_target": {
            target_id: _target_health([item for item in items if item.target_id == target_id])
            for target_id in sorted({item.target_id for item in items})
        },
        "by_mode": {
            mode.value: _metrics([item for item in items if item.mode == mode])
            for mode in ProtectionMode
            if any(item.mode == mode for item in items)
        },
        "by_target": {
            target_id: _metrics([item for item in items if item.target_id == target_id])
            for target_id in sorted({item.target_id for item in items})
        },
        "by_target_and_mode": {
            target_id: {
                mode.value: _metrics(
                    [
                        item
                        for item in items
                        if item.target_id == target_id and item.mode == mode
                    ]
                )
                for mode in ProtectionMode
                if any(
                    item.target_id == target_id and item.mode == mode
                    for item in items
                )
            }
            for target_id in sorted({item.target_id for item in items})
        },
        "protection_delta_by_target": {
            target_id: _protection_delta([item for item in items if item.target_id == target_id])
            for target_id in sorted({item.target_id for item in items})
        },
        "by_attack_family": {
            family: _metrics(
                [item for item in items if item.attacker_metadata.get("family") == family]
            )
            for family in sorted(
                {item.attacker_metadata.get("family") for item in items if item.attacker_metadata.get("family")}
            )
        },
        "by_attack_technique": {
            technique: _metrics(
                [item for item in items if item.attacker_metadata.get("technique") == technique]
            )
            for technique in sorted(
                {item.attacker_metadata.get("technique") for item in items if item.attacker_metadata.get("technique")}
            )
        },
        "by_scenario": {
            scenario_id: _metrics([item for item in items if item.scenario_id == scenario_id])
            for scenario_id in sorted({item.scenario_id for item in items})
        },
        "protected_vs_unprotected": _protection_delta(items),
    }


def write_results_jsonl(
    results: tuple[EpisodeResult, ...] | list[EpisodeResult],
    path: str | Path,
) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [item.to_json() for item in results]
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def stable_hash(value: Any) -> str:
    canonical = json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _target_run(target: TargetAgent, scenario: Scenario, injection: str | None) -> TargetRunResult:
    richer = getattr(target, "run_with_result", None)
    if callable(richer):
        try:
            result = richer(scenario, injection)
        except Exception as exc:
            return TargetRunResult(
                (),
                GenerationMetadata(
                    status=TargetStatus.INTERNAL_ERROR,
                    provider="adapter",
                    model=target.target_id,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                ),
            )
        if not isinstance(result, TargetRunResult):
            return TargetRunResult(
                (),
                GenerationMetadata(
                    status=TargetStatus.INTERNAL_ERROR,
                    provider="adapter",
                    model=target.target_id,
                    error_type="InvalidAdapterContract",
                    error_message="run_with_result() did not return TargetRunResult",
                ),
            )
        return result

    try:
        plan = tuple(target.run(scenario, injection))
    except Exception as exc:
        return TargetRunResult(
            (),
            GenerationMetadata(
                status=TargetStatus.INTERNAL_ERROR,
                provider="legacy_target",
                model=target.target_id,
                error_type=type(exc).__name__,
                error_message=str(exc),
            ),
        )
    return TargetRunResult(
        plan,
        GenerationMetadata(
            status=TargetStatus.VALID_PLAN,
            provider="legacy_target",
            model=target.target_id,
        ),
    )


def _metrics(items: list[EpisodeResult]) -> dict[str, Any]:
    valid = [item for item in items if item.security_evaluated]
    model_valid = _unique_model_observations(valid)
    clean_known = _unique_clean_observations(items)
    decisions = [record.decision.type for item in valid for record in item.records]
    denominator = len(decisions)

    iv_count = sum(bool(item.violations) for item in valid)
    drift_count = sum(item.drift.changed for item in model_valid if item.drift is not None)
    escalation_count = sum(
        item.drift.security_escalation for item in model_valid if item.drift is not None
    )
    contraction_count = sum(
        item.drift.security_contraction for item in model_valid if item.drift is not None
    )
    mixed_drift_count = sum(
        item.drift.security_escalation and item.drift.security_contraction
        for item in model_valid
        if item.drift is not None
    )
    escalation_only_count = sum(
        item.drift.security_escalation and not item.drift.security_contraction
        for item in model_valid
        if item.drift is not None
    )
    contraction_only_count = sum(
        item.drift.security_contraction and not item.drift.security_escalation
        for item in model_valid
        if item.drift is not None
    )
    plan_change_count = sum(bool(item.plan_changed) for item in model_valid)
    objective_known = [item for item in model_valid if item.attack_objective_success is not None]
    objective_success_count = sum(bool(item.attack_objective_success) for item in objective_known)
    off_objective_escalation_count = sum(
        item.drift is not None
        and item.drift.security_escalation
        and item.attack_objective_success is False
        for item in objective_known
    )
    clean_success = sum(bool(item.clean_utility_success) for item in clean_known)
    rewards = [item.reward for item in valid if item.reward is not None]

    iv_rate = _rate_or_none(iv_count, len(valid))
    drift_rate = _rate_or_none(drift_count, len(model_valid))
    escalation_rate = _rate_or_none(escalation_count, len(model_valid))
    contraction_rate = _rate_or_none(contraction_count, len(model_valid))
    mixed_drift_rate = _rate_or_none(mixed_drift_count, len(model_valid))
    escalation_only_rate = _rate_or_none(escalation_only_count, len(model_valid))
    contraction_only_rate = _rate_or_none(contraction_only_count, len(model_valid))
    plan_change_rate = _rate_or_none(plan_change_count, len(model_valid))
    objective_success_rate = _rate_or_none(objective_success_count, len(objective_known))
    off_objective_escalation_rate = _rate_or_none(
        off_objective_escalation_count, len(objective_known)
    )
    clean_rate = _rate_or_none(clean_success, len(clean_known))

    return {
        "episodes": len(items),
        "valid_security_episodes": len(valid),
        "valid_security_episode_rate": _rate(len(valid), len(items)),
        "target_failure_rate": _rate(len(items) - len(valid), len(items)),
        "baseline_generation_valid_rate": _rate(
            sum(item.baseline_generation.valid for item in items), len(items)
        ),
        "candidate_generation_valid_rate": _rate(
            sum(item.candidate_generation.valid for item in items), len(items)
        ),
        "candidate_status_counts": _status_counts(item.candidate_generation for item in items),
        "invariant_violation_count": iv_count,
        "invariant_violation_rate": iv_rate,
        "invariant_violation_rate_ci95": _wilson95(iv_count, len(valid)),
        "model_security_observations": len(model_valid),
        "behavioral_drift_count": drift_count,
        "behavioral_drift_rate": drift_rate,
        "behavioral_drift_rate_ci95": _wilson95(drift_count, len(model_valid)),
        "security_escalation_count": escalation_count,
        "security_escalation_rate": escalation_rate,
        "security_escalation_rate_ci95": _wilson95(escalation_count, len(model_valid)),
        "security_contraction_count": contraction_count,
        "security_contraction_rate": contraction_rate,
        "security_contraction_rate_ci95": _wilson95(contraction_count, len(model_valid)),
        "mixed_drift_count": mixed_drift_count,
        "mixed_drift_rate": mixed_drift_rate,
        "mixed_drift_rate_ci95": _wilson95(mixed_drift_count, len(model_valid)),
        "security_escalation_only_count": escalation_only_count,
        "security_escalation_only_rate": escalation_only_rate,
        "security_escalation_only_rate_ci95": _wilson95(escalation_only_count, len(model_valid)),
        "security_contraction_only_count": contraction_only_count,
        "security_contraction_only_rate": contraction_only_rate,
        "security_contraction_only_rate_ci95": _wilson95(contraction_only_count, len(model_valid)),
        "plan_change_count": plan_change_count,
        "plan_change_rate": plan_change_rate,
        "plan_change_rate_ci95": _wilson95(plan_change_count, len(model_valid)),
        "attack_objective_observations": len(objective_known),
        "attack_objective_success_count": objective_success_count,
        "attack_objective_success_rate": objective_success_rate,
        "attack_objective_success_rate_ci95": _wilson95(
            objective_success_count, len(objective_known)
        ),
        "off_objective_security_escalation_count": off_objective_escalation_count,
        "off_objective_security_escalation_rate": off_objective_escalation_rate,
        "off_objective_security_escalation_rate_ci95": _wilson95(
            off_objective_escalation_count, len(objective_known)
        ),
        "deny_action_rate": _rate_or_none(sum(decision == DecisionType.DENY for decision in decisions), denominator),
        "approval_action_rate": _rate_or_none(
            sum(decision == DecisionType.REQUIRE_APPROVAL for decision in decisions), denominator
        ),
        "clean_utility_observations": len(clean_known),
        "clean_utility_success_count": clean_success,
        "clean_utility_success_rate": clean_rate,
        "clean_utility_success_rate_ci95": _wilson95(clean_success, len(clean_known)),
        "mcp_remote_call_count": sum(item.mcp_remote_call_count for item in valid),
        "mcp_observed_action_count": sum(
            state == "observed" for item in valid for state in item.mcp_call_states
        ),
        "mcp_not_called_action_count": sum(
            state == "not_called" for item in valid for state in item.mcp_call_states
        ),
        "mcp_indeterminate_action_count": sum(
            state == "indeterminate" for item in valid for state in item.mcp_call_states
        ),
        "mcp_untrusted_ingress_observations": sum(
            bool(item.ingress and item.ingress.get("trust") == "untrusted")
            for item in model_valid
        ),
        "mean_terminal_reward": (sum(rewards) / len(rewards)) if rewards else None,
    }


def _unique_model_observations(items: list[EpisodeResult]) -> list[EpisodeResult]:
    """Deduplicate the same target plan evaluated in protected/unprotected modes."""

    unique: dict[tuple[str, str, str, str], EpisodeResult] = {}
    for item in items:
        key = (item.target_id, item.scenario_id, item.attacker_id, item.injection_hash)
        unique.setdefault(key, item)
    return list(unique.values())


def _unique_clean_observations(items: list[EpisodeResult]) -> list[EpisodeResult]:
    """Deduplicate clean baselines repeated across many attack candidates.

    A 25-candidate scenario should contribute one clean-utility observation per
    target/mode, not 25 identical observations that artificially tighten a CI.
    """

    unique: dict[tuple[str, str, str, str], EpisodeResult] = {}
    for item in items:
        if item.clean_utility_success is None:
            continue
        key = (
            item.target_id,
            item.scenario_id,
            item.mode.value,
            stable_hash(item.baseline_plan),
        )
        unique.setdefault(key, item)
    return list(unique.values())


def _attacker_metadata(attacker: Attacker) -> dict[str, str]:
    metadata = getattr(attacker, "metadata", None)
    if not callable(metadata):
        return {}
    try:
        raw = metadata()
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def _target_health(items: list[EpisodeResult]) -> dict[str, Any]:
    generations: list[GenerationMetadata] = []
    for item in items:
        generations.extend((item.baseline_generation, item.candidate_generation))
    unique = [generation for generation in generations if not generation.cache_hit]
    if not unique:
        unique = generations
    valid = sum(generation.valid for generation in unique)
    latencies = [generation.latency_ms for generation in unique if generation.latency_ms is not None]
    input_tokens = [generation.input_tokens for generation in unique if generation.input_tokens is not None]
    output_tokens = [generation.output_tokens for generation in unique if generation.output_tokens is not None]
    reasoning_tokens = [
        generation.reasoning_tokens for generation in unique if generation.reasoning_tokens is not None
    ]
    reasoning_chars = [generation.reasoning_chars for generation in unique]
    attempts = [generation.attempts for generation in unique]
    reasoning_observed = any(
        (generation.reasoning_tokens or 0) > 0 or generation.reasoning_chars > 0
        for generation in unique
    )
    reasoning_mismatch_targets = _reasoning_mode_mismatch_targets(items)

    # A CLI label such as ``--reasoning-mode off`` records intended external
    # configuration; it does not prove that the serving stack actually honored
    # it. Compare that label with server-reported reasoning telemetry so
    # experiments cannot silently claim a reasoning-off condition while the
    # model emits reasoning tokens.
    reasoning_labels = sorted(
        {
            item.target_metadata.get("reasoning_mode_label")
            for item in items
            if item.target_metadata.get("reasoning_mode_label")
        }
    )
    if reasoning_tokens:
        reported_reasoning_activity: bool | None = any(value > 0 for value in reasoning_tokens)
    elif any(reasoning_chars):
        reported_reasoning_activity = True
    else:
        reported_reasoning_activity = None

    reasoning_mode_label_mismatch: bool | None = None
    if len(reasoning_labels) == 1 and reasoning_labels[0] == "off":
        if reported_reasoning_activity is not None:
            reasoning_mode_label_mismatch = reported_reasoning_activity

    finish_reasons: dict[str, int] = {}
    for generation in unique:
        if generation.finish_reason is not None:
            finish_reasons[generation.finish_reason] = finish_reasons.get(generation.finish_reason, 0) + 1
    return {
        "generation_observations": len(generations),
        "unique_generation_calls": len(unique),
        "valid_generation_rate": _rate(valid, len(unique)),
        "generation_failure_count": len(unique) - valid,
        "status_counts": _status_counts(unique),
        "finish_reason_counts": dict(sorted(finish_reasons.items())),
        "mean_latency_ms": _mean_or_none(latencies),
        "input_token_observations": len(input_tokens),
        "total_input_tokens": sum(input_tokens) if input_tokens else None,
        "mean_input_tokens": _mean_or_none(input_tokens),
        "output_token_observations": len(output_tokens),
        "total_output_tokens": sum(output_tokens) if output_tokens else None,
        "mean_output_tokens": _mean_or_none(output_tokens),
        "reasoning_token_observations": len(reasoning_tokens),
        "total_reasoning_tokens": sum(reasoning_tokens) if reasoning_tokens else None,
        "mean_reasoning_tokens": _mean_or_none(reasoning_tokens),
        "mean_reasoning_chars": _mean_or_none(reasoning_chars),
        "reasoning_mode_labels": reasoning_labels,
        "reported_reasoning_activity": reported_reasoning_activity,
        "reasoning_mode_label_mismatch": reasoning_mode_label_mismatch,
        "reasoning_observed": reasoning_observed,
        "reasoning_mode_mismatch": bool(reasoning_mismatch_targets),
        "reasoning_mode_mismatch_targets": reasoning_mismatch_targets,
        "mean_attempts": _mean_or_none(attempts),
    }


def _reasoning_mode_mismatch_targets(items: list[EpisodeResult]) -> list[str]:
    mismatches: list[str] = []
    for target_id in sorted({item.target_id for item in items}):
        target_items = [item for item in items if item.target_id == target_id]
        if not target_items:
            continue
        label = target_items[0].target_metadata.get("reasoning_mode_label")
        if label != "off":
            continue
        generations = [
            generation
            for item in target_items
            for generation in (item.baseline_generation, item.candidate_generation)
            if not generation.cache_hit
        ]
        if not generations:
            generations = [
                generation
                for item in target_items
                for generation in (item.baseline_generation, item.candidate_generation)
            ]
        if any(
            (generation.reasoning_tokens or 0) > 0 or generation.reasoning_chars > 0
            for generation in generations
        ):
            mismatches.append(target_id)
    return mismatches


def _status_counts(generations: Any) -> dict[str, int]:
    counts = {status.value: 0 for status in TargetStatus}
    for generation in generations:
        counts[generation.status.value] += 1
    return {key: value for key, value in counts.items() if value}


def _protection_delta(items: list[EpisodeResult]) -> dict[str, float | int | None] | None:
    protected = [item for item in items if item.mode == ProtectionMode.PROTECTED]
    unprotected = [item for item in items if item.mode == ProtectionMode.UNPROTECTED]
    if not protected or not unprotected:
        return None
    p = _metrics(protected)
    u = _metrics(unprotected)
    iv_p = p["invariant_violation_rate"]
    iv_u = u["invariant_violation_rate"]
    reward_p = p["mean_terminal_reward"]
    reward_u = u["mean_terminal_reward"]
    clean_p = p["clean_utility_success_rate"]
    clean_u = u["clean_utility_success_rate"]
    return {
        "protected_valid_security_episodes": p["valid_security_episodes"],
        "unprotected_valid_security_episodes": u["valid_security_episodes"],
        "invariant_violation_rate_reduction": (
            iv_u - iv_p if iv_u is not None and iv_p is not None else None
        ),
        "mean_terminal_reward_reduction": (
            reward_u - reward_p if reward_u is not None and reward_p is not None else None
        ),
        "clean_utility_delta": (
            clean_p - clean_u if clean_p is not None and clean_u is not None else None
        ),
    }


def _rate(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def _rate_or_none(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _wilson95(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    phat = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (phat + z2 / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt((phat * (1.0 - phat) + z2 / (4.0 * total)) / total)
        / denominator
    )
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _mean_or_none(values: list[float | int]) -> float | None:
    return None if not values else sum(values) / len(values)


def _action_dict(action: PlannedAction) -> dict[str, Any]:
    return {
        "tool": action.tool,
        "arguments": {
            key: {
                "data": value.data,
                "provenance": {
                    "source": value.provenance.source,
                    "trust": value.provenance.trust.value,
                    "detail": value.provenance.detail,
                    "confidentiality": value.provenance.confidentiality.value,
                    "parents": list(value.provenance.parents),
                },
            }
            for key, value in sorted(action.arguments.items())
        },
    }


def _plans_plain_differ(
    baseline: tuple[PlannedAction, ...] | list[PlannedAction],
    candidate: tuple[PlannedAction, ...] | list[PlannedAction],
) -> bool:
    """Return whether externally proposed tool names/plain arguments changed.

    Provenance labels are intentionally excluded. This metric is a broad plan
    change diagnostic, not an attack-success or security-drift metric.
    """

    def plain(plan):
        return [(action.tool, action.plain_arguments()) for action in plan]

    return plain(baseline) != plain(candidate)


def _effect_dict(effect: Effect) -> dict[str, Any]:
    return {
        "kind": effect.kind,
        "tool": effect.tool,
        "attributes": effect.attributes,
        "provenance": {
            key: {
                "source": provenance.source,
                "trust": provenance.trust.value,
                "detail": provenance.detail,
                "confidentiality": provenance.confidentiality.value,
                "parents": list(provenance.parents),
            }
            for key, provenance in sorted(effect.provenance.items())
        },
        "action_fingerprint": effect.action_fingerprint,
    }


def _normalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Value):
        return _action_dict(PlannedAction("_", {"value": value}))["arguments"]["value"]
    if is_dataclass(value):
        return _normalize(asdict(value))
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in sorted(value.items(), key=lambda x: str(x[0]))}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    return value
