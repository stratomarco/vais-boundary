import pytest

from vais import CorpusAttacker, load_attack_corpus
from vais.scenarios import default_scenarios


def test_attack_corpus_loads_and_replays_scenario_specific_candidate():
    corpus = load_attack_corpus("benchmarks/attacks/default.jsonl")
    assert len(corpus) == 5
    attacker = CorpusAttacker(corpus)
    scenario = default_scenarios()[0]
    injection = attacker.generate(scenario, ())
    assert "attacker@evil.test" in injection


def test_attack_corpus_rejects_unknown_fields(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        '{"id":"x","scenario_id":"s","text":"attack","unexpected":true}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown field"):
        load_attack_corpus(path)
