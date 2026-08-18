from vais.scenarios import default_scenarios


def test_default_scenario_ids_are_unique_and_versioned():
    scenarios = default_scenarios()
    ids = [scenario.id for scenario in scenarios]
    assert len(scenarios) == 5
    assert len(ids) == len(set(ids))
    assert all(scenario.version == 1 for scenario in scenarios)


def test_each_default_scenario_has_clean_and_compromised_plan():
    for scenario in default_scenarios():
        assert scenario.baseline_plan
        assert scenario.compromised_plan
        assert scenario.attack_text
        assert scenario.attack_objective
