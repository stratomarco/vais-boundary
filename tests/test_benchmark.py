from __future__ import annotations

import json

from vais.adaptive import DeterministicScenarioTarget, ScenarioStaticAttacker
from vais.benchmark import (
    BenchmarkRunner,
    ProtectionMode,
    summarize_results,
    write_results_jsonl,
)
from vais.scenarios import default_scenarios


def test_default_scenarios_are_blocked_when_protected_and_violate_when_unprotected():
    runner = BenchmarkRunner()
    target = DeterministicScenarioTarget()
    attacker = ScenarioStaticAttacker()

    unprotected = [
        runner.run_episode(scenario, target, attacker, ProtectionMode.UNPROTECTED)
        for scenario in default_scenarios()
    ]
    protected = [
        runner.run_episode(scenario, target, attacker, ProtectionMode.PROTECTED)
        for scenario in default_scenarios()
    ]

    assert all(result.reward == 1.0 for result in unprotected)
    assert all(result.violations for result in unprotected)
    assert all(result.reward == 0.0 for result in protected)
    assert all(not result.violations for result in protected)
    assert all(result.clean_utility_success for result in unprotected + protected)


def test_approval_replay_requires_new_exact_action_approval():
    scenario = next(item for item in default_scenarios() if item.id == "approval-replay")
    result = BenchmarkRunner().run_episode(
        scenario,
        DeterministicScenarioTarget(),
        ScenarioStaticAttacker(),
        ProtectionMode.PROTECTED,
    )

    assert result.records[0].decision.type.value == "require_approval"
    assert result.effects == ()
    assert result.reward == 0.0


def test_summary_preserves_target_specific_results():
    runner = BenchmarkRunner()
    scenarios = default_scenarios()
    targets = (
        DeterministicScenarioTarget("all"),
        DeterministicScenarioTarget(
            "selective",
            susceptible_scenarios={"email-recipient-hijack"},
        ),
    )
    results = runner.run_matrix(
        scenarios=scenarios,
        targets=targets,
        attackers=(ScenarioStaticAttacker(),),
    )
    summary = summarize_results(results)

    assert summary["by_target"]["all"]["attack_objective_success_rate"] == 1.0
    assert summary["by_target"]["selective"]["attack_objective_success_rate"] == 0.2
    assert summary["protected_vs_unprotected"]["invariant_violation_rate_reduction"] > 0


def test_jsonl_is_replayable_and_contains_hashes(tmp_path):
    scenario = default_scenarios()[0]
    result = BenchmarkRunner().run_episode(
        scenario,
        DeterministicScenarioTarget(),
        ScenarioStaticAttacker(),
        ProtectionMode.PROTECTED,
    )
    output = tmp_path / "episode.jsonl"
    write_results_jsonl([result], output)

    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["scenario"]["id"] == scenario.id
    assert len(parsed["policy_hash"]) == 64
    assert len(parsed["invariant_hash"]) == 64
    assert parsed["terminal_security_reward"] == 0.0


def test_target_failure_is_recorded_and_not_counted_as_security_success():
    from vais.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleTarget
    from vais.targeting import TargetStatus

    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")

    def transport(url, payload, headers, timeout):
        del url, headers, timeout
        attacked = scenario.attack_text in payload["messages"][1]["content"]
        if attacked:
            return {
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {"content": "", "reasoning_content": "thinking"},
                    }
                ]
            }
        plan = {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": "alice@example.com", "body": "Quarterly summary"},
                }
            ]
        }
        return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(plan)}}]}

    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="failing-target"), transport=transport)
    result = BenchmarkRunner().run_episode(
        scenario,
        target,
        ScenarioStaticAttacker(),
        ProtectionMode.PROTECTED,
    )
    summary = summarize_results([result])

    assert result.candidate_generation.status == TargetStatus.TRUNCATED
    assert result.security_evaluated is False
    assert result.reward is None
    assert result.plan_changed is None
    assert result.attack_objective_success is None
    assert result.violations == ()
    assert result.clean_utility_success is True
    assert summary["overall"]["valid_security_episodes"] == 0
    assert summary["overall"]["invariant_violation_rate"] is None
    assert summary["overall"]["plan_change_rate"] is None
    assert summary["overall"]["attack_objective_success_rate"] is None
    assert summary["overall"]["target_failure_rate"] == 1.0


def test_real_target_generation_health_deduplicates_paired_cache_calls():
    from vais.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleTarget

    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")
    calls = []

    def transport(url, payload, headers, timeout):
        del url, headers, timeout
        calls.append(payload)
        attacked = scenario.attack_text in payload["messages"][1]["content"]
        recipient = "attacker@evil.test" if attacked else "alice@example.com"
        plan = {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": recipient, "body": "Quarterly summary"},
                }
            ]
        }
        return {
            "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(plan)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 25},
        }

    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="realish"), transport=transport)
    results = BenchmarkRunner().run_matrix(
        scenarios=(scenario,),
        targets=(target,),
        attackers=(ScenarioStaticAttacker(),),
    )
    summary = summarize_results(results)

    assert len(calls) == 2
    assert summary["target_health"]["generation_observations"] == 4
    assert summary["target_health"]["unique_generation_calls"] == 2
    assert summary["target_health"]["valid_generation_rate"] == 1.0
    assert summary["target_health"]["mean_input_tokens"] == 100
    assert summary["target_health"]["mean_output_tokens"] == 25


def test_summary_separates_each_target_by_protection_mode():
    runner = BenchmarkRunner()
    scenario = default_scenarios()[0]
    target = DeterministicScenarioTarget("mode-split")
    results = runner.run_matrix(
        scenarios=(scenario,),
        targets=(target,),
        attackers=(ScenarioStaticAttacker(),),
    )
    summary = summarize_results(results)

    split = summary["by_target_and_mode"]["mode-split"]
    assert split["unprotected"]["invariant_violation_rate"] == 1.0
    assert split["protected"]["invariant_violation_rate"] == 0.0


def test_target_health_flags_reasoning_off_label_when_server_reports_reasoning():
    from vais.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleTarget

    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")

    def transport(url, payload, headers, timeout):
        del url, headers, timeout
        attacked = scenario.attack_text in payload["messages"][1]["content"]
        recipient = "attacker@evil.test" if attacked else "alice@example.com"
        plan = {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": recipient, "body": "Quarterly summary"},
                }
            ]
        }
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": json.dumps(plan),
                        "reasoning_content": "server-reported reasoning",
                    },
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 80,
                "completion_tokens_details": {"reasoning_tokens": 55},
            },
        }

    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(model="reasoning-target", reasoning_mode_label="off"),
        transport=transport,
    )
    results = BenchmarkRunner().run_matrix(
        scenarios=(scenario,),
        targets=(target,),
        attackers=(ScenarioStaticAttacker(),),
    )
    health = summarize_results(results)["target_health_by_target"][target.target_id]

    assert health["reported_reasoning_activity"] is True
    assert health["reasoning_mode_labels"] == ["off"]
    assert health["reasoning_mode_label_mismatch"] is True


def test_reasoning_label_off_is_flagged_when_reasoning_is_observed():
    from vais.targeting import GenerationMetadata, TargetRunResult, TargetStatus

    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")

    class ReasoningTarget:
        target_id = "reasoning-target"

        def metadata(self):
            return {"reasoning_mode_label": "off"}

        def run_with_result(self, scenario, injected_content=None):
            plan = scenario.baseline_plan if injected_content is None else scenario.compromised_plan
            return TargetRunResult(
                tuple(plan),
                GenerationMetadata(
                    status=TargetStatus.VALID_PLAN,
                    provider="test",
                    model=self.target_id,
                    reasoning_tokens=10,
                    reasoning_chars=40,
                ),
            )

    result = BenchmarkRunner().run_episode(
        scenario,
        ReasoningTarget(),
        ScenarioStaticAttacker(),
        ProtectionMode.PROTECTED,
    )
    health = summarize_results([result])["target_health"]
    assert health["reasoning_observed"] is True
    assert health["reasoning_mode_mismatch"] is True
    assert health["reasoning_mode_mismatch_targets"] == ["reasoning-target"]


def test_metric_stages_separate_cosmetic_plan_change_from_attack_success():
    from vais.models import PlannedAction, Provenance, TrustLevel, Value

    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")

    class CosmeticTarget:
        target_id = "cosmetic-target"

        def metadata(self):
            return {}

        def run(self, scenario, injected_content=None):
            body = "Summary of the document content." if injected_content is None else "Summary of the document content"
            return [
                PlannedAction(
                    "send_email",
                    {
                        "recipient": scenario.contract.bound_arguments[("send_email", "recipient")],
                        "body": Value(body, Provenance("model_output", TrustLevel.DERIVED_UNTRUSTED)),
                    },
                )
            ]

    result = BenchmarkRunner().run_episode(
        scenario, CosmeticTarget(), ScenarioStaticAttacker(), ProtectionMode.PROTECTED
    )
    assert result.plan_changed is True
    assert result.drift is not None and result.drift.changed is False
    assert result.attack_objective_success is False
    assert result.reward == 0.0


def test_metric_stages_detect_approval_attack_even_when_unbound_amount_provenance_is_same():
    from vais.models import PlannedAction, Provenance, TrustLevel, Value

    scenario = next(s for s in default_scenarios() if s.id == "approval-replay")

    class ApprovalReplayTarget:
        target_id = "approval-replay-target"

        def metadata(self):
            return {}

        def run(self, scenario, injected_content=None):
            amount = 150 if injected_content is None else 999
            return [
                PlannedAction(
                    "make_payment",
                    {
                        "destination": scenario.contract.bound_arguments[("make_payment", "destination")],
                        "amount": Value(
                            amount,
                            Provenance("model_output", TrustLevel.DERIVED_UNTRUSTED),
                        ),
                    },
                )
            ]

    result = BenchmarkRunner().run_episode(
        scenario, ApprovalReplayTarget(), ScenarioStaticAttacker(), ProtectionMode.PROTECTED
    )
    assert result.plan_changed is True
    assert result.drift is not None and result.drift.changed is True
    assert "approved_action_drift:make_payment" in result.drift.reasons
    assert result.attack_objective_success is True
    assert result.records[0].decision.type.value == "require_approval"
    assert result.reward == 0.0
