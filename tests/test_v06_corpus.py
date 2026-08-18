from collections import Counter

from vais.adaptive import corpus_entry_attackers, load_attack_corpus
from vais.benchmark import BenchmarkRunner, ProtectionMode, summarize_results
from vais.adaptive import DeterministicScenarioTarget
from vais.scenarios import default_scenarios


def test_v06_static_corpus_has_125_balanced_candidates():
    corpus = load_attack_corpus("benchmarks/attacks/static-v0.6-125.jsonl")
    assert len(corpus) == 125
    counts = Counter(item.scenario_id for item in corpus)
    assert set(counts.values()) == {25}
    assert len(counts) == 5
    assert all(item.metadata.get("technique") for item in corpus)
    assert all(item.metadata.get("corpus") == "static-v0.6-125" for item in corpus)


def test_corpus_expansion_runs_every_candidate_only_on_its_scenario():
    corpus = load_attack_corpus("benchmarks/attacks/static-v0.6-125.jsonl")
    results = BenchmarkRunner().run_matrix(
        scenarios=default_scenarios(),
        targets=(DeterministicScenarioTarget(),),
        attackers=corpus_entry_attackers(corpus),
        modes=(ProtectionMode.UNPROTECTED, ProtectionMode.PROTECTED),
    )
    assert len(results) == 250
    assert len({item.injection_hash for item in results}) == 125
    assert all(item.attacker_metadata.get("attack_id") for item in results)


def test_clean_utility_is_not_inflated_by_attack_count():
    corpus = load_attack_corpus("benchmarks/attacks/static-v0.6-125.jsonl")
    results = BenchmarkRunner().run_matrix(
        scenarios=default_scenarios(),
        targets=(DeterministicScenarioTarget(),),
        attackers=corpus_entry_attackers(corpus),
        modes=(ProtectionMode.UNPROTECTED, ProtectionMode.PROTECTED),
    )
    summary = summarize_results(results)
    assert summary["by_mode"]["protected"]["clean_utility_observations"] == 5
    assert summary["by_mode"]["unprotected"]["clean_utility_observations"] == 5
    assert summary["overall"]["clean_utility_observations"] == 10
