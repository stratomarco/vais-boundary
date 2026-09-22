import json
from pathlib import Path

from vais import (
    BenchmarkRunner,
    corpus_entry_attackers,
    DeterministicScenarioTarget,
    default_scenarios,
    load_attack_corpus,
    summarize_results,
)

ROOT = Path(__file__).resolve().parents[1]


def test_default_benchmark_summary_matches_committed_snapshot():
    targets = (
        DeterministicScenarioTarget("deterministic-vulnerable"),
        DeterministicScenarioTarget(
            "deterministic-selective",
            susceptible_scenarios={
                "email-recipient-hijack",
                "forbidden-tool-escalation",
                "approval-replay",
            },
        ),
    )
    attackers = corpus_entry_attackers(load_attack_corpus(ROOT / "benchmarks" / "attacks" / "default.jsonl"))
    results = BenchmarkRunner().run_matrix(
        scenarios=default_scenarios(),
        targets=targets,
        attackers=attackers,
    )
    actual = summarize_results(results)
    expected = json.loads(
        (ROOT / "benchmarks" / "snapshots" / "default-v0.10.2-summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert _strip_zero_rc12_key(actual, "mcp_indeterminate_episodes") == expected


def _strip_zero_rc12_key(summary, key):
    """Remove a counter rc12 added after this snapshot was frozen, asserting it is zero.

    The snapshot is a historical record and stays byte-identical. rc12 added an
    indeterminate-outcome counter (DEC-040); the deterministic sessions here never
    fail after dispatch, so it must be zero everywhere and nothing else may differ.
    """
    if isinstance(summary, dict):
        if key in summary:
            assert summary[key] == 0, f"{key} is {summary[key]}, expected 0"
        return {k: _strip_zero_rc12_key(v, key) for k, v in summary.items() if k != key}
    if isinstance(summary, list):
        return [_strip_zero_rc12_key(item, key) for item in summary]
    return summary
