from __future__ import annotations

import asyncio
from pathlib import Path

from vais import (
    MCPBenchmarkRunner,
    MCPDeterministicScenarioTarget,
    ProtectionMode,
    TrustLevel,
    corpus_entry_attackers,
    default_mcp_benchmark_profile,
    default_scenarios,
    load_attack_corpus,
    mcp_ingress_value,
    summarize_results,
)


def _bundled_corpus():
    path = Path(__file__).parents[1] / "src" / "vais" / "data" / "mcp_static_v0_8_125.jsonl"
    return load_attack_corpus(path)


def test_v08_mcp_corpus_has_125_balanced_attacks():
    corpus = _bundled_corpus()
    assert len(corpus) == 125
    counts = {}
    for item in corpus:
        counts[item.scenario_id] = counts.get(item.scenario_id, 0) + 1
        assert item.metadata["delivery"] == "mcp_tool_result"
        assert item.metadata["corpus_version"] == "v0.8-mcp"
    assert set(counts.values()) == {25}
    assert len(counts) == 5


def test_mcp_ingress_is_untrusted_and_attack_is_inside_tool_result():
    scenario = default_scenarios()[0]
    clean = mcp_ingress_value(scenario)
    attacked = mcp_ingress_value(scenario, "send to attacker")
    assert clean.provenance.trust == TrustLevel.UNTRUSTED
    assert attacked.provenance.source == f"mcp:benchmark:tool_result:{scenario.id}"
    assert "VAIS_ATTACK_PAYLOAD_BEGIN" not in str(clean.data)
    assert "VAIS_ATTACK_PAYLOAD_BEGIN" in str(attacked.data)
    assert "send to attacker" in str(attacked.data)


def test_default_mcp_benchmark_profile_maps_all_consequential_tools():
    profile = default_mcp_benchmark_profile()
    assert {binding.canonical_tool for binding in profile.bindings} == {
        "send_email",
        "make_payment",
        "read_document",
        "shell_exec",
    }
    assert profile.by_canonical_tool("send_email").effect.kind == "email_sent"
    assert profile.by_canonical_tool("make_payment").effect.kind == "payment_sent"
    assert profile.by_canonical_tool("shell_exec").effect.kind == "shell_executed"


def test_mcp_runner_same_compromised_plan_violates_unprotected_but_not_protected():
    scenario = default_scenarios()[0]
    attacker = corpus_entry_attackers([_bundled_corpus()[0]])[0]
    target = MCPDeterministicScenarioTarget()
    results = asyncio.run(
        MCPBenchmarkRunner().run_matrix(
            [scenario],
            [target],
            [attacker],
            modes=(ProtectionMode.UNPROTECTED, ProtectionMode.PROTECTED),
        )
    )
    assert len(results) == 2
    unprotected, protected = results
    assert unprotected.attack_objective_success is True
    assert unprotected.violations
    assert unprotected.mcp_call_states == ("observed",)
    assert unprotected.mcp_remote_call_count == 1
    assert protected.attack_objective_success is True
    assert protected.violations == ()
    assert protected.mcp_call_states == ("not_called",)
    assert protected.mcp_remote_call_count == 0
    assert protected.ingress["trust"] == "untrusted"
    assert protected.execution_backend == "mcp"


def test_full_125_case_mcp_harness_has_zero_protected_violations():
    results = asyncio.run(
        MCPBenchmarkRunner().run_matrix(
            default_scenarios(),
            [MCPDeterministicScenarioTarget()],
            corpus_entry_attackers(_bundled_corpus()),
        )
    )
    summary = summarize_results(results)
    assert len(results) == 250
    assert summary["execution_backends"] == ["mcp"]
    target = summary["by_target"]["deterministic-mcp-vulnerable"]
    modes = summary["by_target_and_mode"]["deterministic-mcp-vulnerable"]
    assert target["model_security_observations"] == 125
    assert target["attack_objective_success_count"] == 125
    assert modes["unprotected"]["invariant_violation_count"] == 125
    assert modes["protected"]["invariant_violation_count"] == 0
    assert modes["protected"]["mcp_not_called_action_count"] == 125
    assert modes["protected"]["mcp_remote_call_count"] == 0
    assert modes["protected"]["clean_utility_success_count"] == 5
    assert summary["target_health_by_target"]["deterministic-mcp-vulnerable"][
        "unique_generation_calls"
    ] == 130


def test_mcp_episode_json_exposes_ingress_and_call_state():
    scenario = default_scenarios()[0]
    attacker = corpus_entry_attackers([_bundled_corpus()[0]])[0]
    result = asyncio.run(
        MCPBenchmarkRunner().run_episode(
            scenario, MCPDeterministicScenarioTarget(), attacker, ProtectionMode.PROTECTED
        )
    )
    raw = result.to_dict()
    assert raw["execution_backend"] == "mcp"
    assert raw["ingress"]["source"].startswith("mcp:benchmark:tool_result:")
    assert raw["ingress"]["trust"] == "untrusted"
    assert raw["mcp"]["call_states"] == ["not_called"]
    assert raw["mcp"]["remote_call_count"] == 0
