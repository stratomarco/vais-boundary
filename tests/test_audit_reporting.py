from vais.reporting import render_audit_summary


def test_audit_summary_prints_corrected_pipeline_and_reasoning_warning():
    report = {
        "model_side_observations": 10,
        "by_target": {
            "qwen": {
                "observations": 5,
                "plan_change_rate": 0.8,
                "behavioral_drift_rate": 0.8,
                "security_escalation_rate": 0.8,
                "security_contraction_only_rate": 0.0,
                "mixed_drift_rate": 0.0,
                "attack_objective_observations": 5,
                "attack_objective_success_rate": 0.8,
                "off_objective_security_escalation_rate": 0.0,
            },
            "gemma": {
                "observations": 5,
                "plan_change_rate": 0.6,
                "behavioral_drift_rate": 0.2,
                "security_escalation_rate": 0.2,
                "security_contraction_only_rate": 0.0,
                "mixed_drift_rate": 0.0,
                "attack_objective_observations": 5,
                "attack_objective_success_rate": 0.2,
                "off_objective_security_escalation_rate": 0.0,
            },
        },
        "reasoning_mode_audit": {
            "gemma": {"reasoning_mode_mismatch": True},
            "qwen": {"reasoning_mode_mismatch": False},
        },
    }
    text = render_audit_summary(report)
    assert "4/5 80.0%" in text
    assert "3/5 60.0%" in text
    assert "1/5 20.0%" in text
    assert "Sec Escalation" in text
    assert "Off-Obj Esc" in text
    assert "reasoning_mode=off" in text
