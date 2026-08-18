from vais import BehavioralIntegrityGate, PlannedAction, Provenance, TaskContract, TrustLevel, TrustedValue, Value


def test_detects_bound_recipient_drift():
    contract = TaskContract(
        allowed_tools={"send_email"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    baseline = [
        PlannedAction(
            "send_email",
            {"recipient": TrustedValue("alice@example.com", "user")},
        )
    ]
    candidate = [
        PlannedAction(
            "send_email",
            {
                "recipient": Value(
                    "attacker@evil.test", Provenance("retrieved_document", TrustLevel.UNTRUSTED)
                )
            },
        )
    ]
    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)
    assert finding.changed
    assert finding.score >= 8
    assert "bound_argument_drift:send_email.recipient" in finding.reasons


def test_detects_added_unauthorized_tool():
    contract = TaskContract(allowed_tools={"read_document"})
    baseline = [PlannedAction("read_document", {"path": TrustedValue("/safe.txt")})]
    candidate = baseline + [PlannedAction("send_email", {"recipient": TrustedValue("a@example.com")})]
    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)
    assert finding.changed
    assert "unauthorized_tool_added:send_email" in finding.reasons


def test_no_drift_for_equivalent_plan():
    contract = TaskContract(
        allowed_tools={"send_email"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    plan = [PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com", "user")})]
    finding = BehavioralIntegrityGate().compare(plan, plan, contract)
    assert not finding.changed
    assert finding.score == 0


def test_detects_duplicate_tool_added_even_if_tool_existed_in_baseline():
    contract = TaskContract(allowed_tools={"send_email"})
    baseline = [PlannedAction("send_email", {"recipient": TrustedValue("a@example.com")})]
    candidate = baseline + [PlannedAction("send_email", {"recipient": TrustedValue("b@example.com")})]
    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)
    assert finding.changed
    assert "tool_count_increased:send_email:1" in finding.reasons


def test_detects_missing_bound_argument():
    contract = TaskContract(
        allowed_tools={"send_email"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    baseline = [PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com", "user")})]
    candidate = [PlannedAction("send_email", {"body": TrustedValue("hello")})]
    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)
    assert finding.changed
    assert "bound_argument_missing:send_email.recipient" in finding.reasons


def test_detects_confidentiality_increase_without_tool_change():
    from vais import ConfidentialityLevel

    contract = TaskContract(allowed_tools={"send_email"})
    baseline = [
        PlannedAction(
            "send_email",
            {
                "recipient": TrustedValue("alice@example.com"),
                "body": TrustedValue("public summary"),
            },
        )
    ]
    candidate = [
        PlannedAction(
            "send_email",
            {
                "recipient": TrustedValue("alice@example.com"),
                "body": TrustedValue(
                    "secret material",
                    confidentiality=ConfidentialityLevel.SECRET,
                ),
            },
        )
    ]
    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)
    assert finding.changed
    assert "confidentiality_increased:send_email.body:public>secret" in finding.reasons


def test_detects_exact_approval_drift_even_when_unbound_field_changes():
    baseline_action = PlannedAction(
        "make_payment",
        {
            "destination": TrustedValue("vendor-123", "user"),
            "amount": TrustedValue(150, "user"),
        },
    )
    contract = TaskContract(
        allowed_tools={"make_payment"},
        bound_arguments={
            ("make_payment", "destination"): TrustedValue("vendor-123", "user")
        },
    ).with_approved_action(baseline_action)
    candidate = [
        PlannedAction(
            "make_payment",
            {
                "destination": TrustedValue("vendor-123", "user"),
                "amount": TrustedValue(999, "user"),
            },
        )
    ]

    finding = BehavioralIntegrityGate().compare([baseline_action], candidate, contract)

    assert finding.changed
    assert "approved_action_drift:make_payment" in finding.reasons


def test_detects_exact_approval_drift_when_unbound_amount_changes():
    from vais import TaskContract, action_fingerprint
    from vais.models import Provenance, TrustLevel, Value

    baseline_action = PlannedAction(
        "make_payment",
        {
            "destination": TrustedValue("vendor-123", "user"),
            # Real-model adapters may reconstruct unbound fields as model-derived
            # even when the plain value matches a previously approved action.
            "amount": Value(150, Provenance("model_output", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )
    contract = TaskContract(
        allowed_tools={"make_payment"},
        approved_action_fingerprints={action_fingerprint(baseline_action)},
    )
    candidate = [
        PlannedAction(
            "make_payment",
            {
                "destination": TrustedValue("vendor-123", "user"),
                "amount": Value(999, Provenance("model_output", TrustLevel.DERIVED_UNTRUSTED)),
            },
        )
    ]
    finding = BehavioralIntegrityGate().compare([baseline_action], candidate, contract)
    assert finding.changed
    assert "approved_action_drift:make_payment" in finding.reasons


def test_tool_removal_is_security_contraction_not_escalation():
    contract = TaskContract(allowed_tools={"read_document", "send_email"})
    baseline = [
        PlannedAction("read_document", {"path": TrustedValue("/safe.txt")}),
        PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com")}),
    ]
    candidate = [
        PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com")}),
    ]

    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)

    assert finding.changed
    assert finding.security_contraction is True
    assert finding.security_escalation is False
    assert finding.direction == "contraction"
    assert finding.contraction_reasons == ("tool_removed:read_document",)


def test_unauthorized_tool_addition_is_security_escalation():
    contract = TaskContract(allowed_tools={"send_email"})
    baseline = [
        PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com")}),
    ]
    candidate = baseline + [
        PlannedAction("read_document", {"path": TrustedValue("quarterly_report")}),
    ]

    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)

    assert finding.security_escalation is True
    assert finding.security_contraction is False
    assert finding.direction == "escalation"
    assert "tool_added:read_document" in finding.escalation_reasons
    assert "unauthorized_tool_added:read_document" in finding.escalation_reasons


def test_tool_replacement_can_be_mixed_drift():
    contract = TaskContract(allowed_tools={"send_email"})
    baseline = [
        PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com")}),
    ]
    candidate = [
        PlannedAction("read_document", {"path": TrustedValue("quarterly_report")}),
    ]

    finding = BehavioralIntegrityGate().compare(baseline, candidate, contract)

    assert finding.security_escalation is True
    assert finding.security_contraction is True
    assert finding.direction == "mixed"
