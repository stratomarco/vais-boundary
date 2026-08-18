from vais.adaptive import DeterministicScenarioTarget
from vais.benchmark import BenchmarkRunner, ProtectionMode, summarize_results
from vais.reporting import render_console_summary
from vais.scenarios import default_scenarios


def test_console_summary_prints_security_pipeline_columns():
    results = BenchmarkRunner().run_matrix(
        scenarios=default_scenarios(),
        targets=(DeterministicScenarioTarget(),),
        attackers=(),
        modes=(ProtectionMode.PROTECTED,),
    )
    # Empty attacker sets are valid but produce no target rows; construct a normal smoke run.
    from vais.adaptive import ScenarioStaticAttacker
    results = BenchmarkRunner().run_matrix(
        scenarios=default_scenarios(),
        targets=(DeterministicScenarioTarget(),),
        attackers=(ScenarioStaticAttacker(),),
        modes=(ProtectionMode.UNPROTECTED, ProtectionMode.PROTECTED),
    )
    rendered = render_console_summary(summarize_results(results))
    assert "Plan Change" in rendered
    assert "Behav Drift" in rendered
    assert "Sec Escalation" in rendered
    assert "Attack Success" in rendered
    assert "Unprot IVR" in rendered
    assert "Prot IVR" in rendered
    assert "Security pipeline: plan change -> security escalation -> attack objective -> protected impact" in rendered
    assert "100.0% -> 100.0% -> 100.0% -> 0.0%" in rendered
    assert "off_objective_escalation=" in rendered
