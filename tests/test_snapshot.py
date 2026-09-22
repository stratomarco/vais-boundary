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
    assert actual == expected
