from pathlib import Path

from vais import (
    DecisionType,
    PlannedAction,
    Provenance,
    ReferenceMonitor,
    TaskContract,
    TrustLevel,
    TrustedValue,
    Value,
    load_policy,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_policy(ROOT / "policies" / "default.yaml")


def monitor():
    return ReferenceMonitor(POLICY)


def test_allows_bound_recipient():
    contract = TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    action = PlannedAction(
        "send_email",
        {
            "recipient": TrustedValue("alice@example.com", "user"),
            "body": Value("hello", Provenance("model", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )
    assert monitor().evaluate(action, contract).type == DecisionType.ALLOW


def test_denies_recipient_changed_by_untrusted_document():
    contract = TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    action = PlannedAction(
        "send_email",
        {
            "recipient": Value("attacker@evil.test", Provenance("document", TrustLevel.UNTRUSTED)),
            "body": Value("hello", Provenance("document", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )
    decision = monitor().evaluate(action, contract)
    assert decision.type == DecisionType.DENY
    assert "bound_argument_changed:recipient" in decision.reasons


def test_denies_authority_field_even_when_value_matches_but_provenance_is_untrusted():
    contract = TaskContract(allowed_tools={"send_email"}, granted_scopes={"email:send"})
    action = PlannedAction(
        "send_email",
        {
            "recipient": Value("alice@example.com", Provenance("document", TrustLevel.UNTRUSTED)),
            "body": Value("hello", Provenance("model", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )
    decision = monitor().evaluate(action, contract)
    assert decision.type == DecisionType.DENY
    assert "untrusted_authority_argument:recipient" in decision.reasons


def test_denies_tool_not_in_task_contract():
    contract = TaskContract(allowed_tools={"read_document"})
    action = PlannedAction("send_email", {"recipient": TrustedValue("a@example.com")})
    assert monitor().evaluate(action, contract).type == DecisionType.DENY


def test_requires_approval_above_payment_threshold():
    contract = TaskContract(allowed_tools={"make_payment"}, granted_scopes={"payments:send"})
    action = PlannedAction(
        "make_payment",
        {
            "destination": TrustedValue("merchant-123", "user"),
            "amount": TrustedValue(150, "user"),
        },
    )
    assert monitor().evaluate(action, contract).type == DecisionType.REQUIRE_APPROVAL


def test_allows_exact_approved_payment_above_threshold():
    action = PlannedAction(
        "make_payment",
        {
            "destination": TrustedValue("merchant-123", "user"),
            "amount": TrustedValue(150, "user"),
        },
    )
    contract = TaskContract(
        allowed_tools={"make_payment"},
        granted_scopes={"payments:send"},
    ).with_approved_action(action)
    assert monitor().evaluate(action, contract).type == DecisionType.ALLOW


def test_approval_for_one_payment_does_not_authorize_changed_amount():
    approved = PlannedAction(
        "make_payment",
        {
            "destination": TrustedValue("merchant-123", "user"),
            "amount": TrustedValue(150, "user"),
        },
    )
    changed = PlannedAction(
        "make_payment",
        {
            "destination": TrustedValue("merchant-123", "user"),
            "amount": TrustedValue(999, "user"),
        },
    )
    contract = TaskContract(
        allowed_tools={"make_payment"},
        granted_scopes={"payments:send"},
    ).with_approved_action(approved)
    assert monitor().evaluate(changed, contract).type == DecisionType.REQUIRE_APPROVAL


def test_bound_argument_is_enforced_even_when_static_default_is_allow():
    from vais.policy import Policy

    permissive_static_policy = Policy(default_action="allow", tools={})
    ref_monitor = ReferenceMonitor(permissive_static_policy)
    contract = TaskContract(
        allowed_tools={"custom_tool"},
        bound_arguments={("custom_tool", "destination"): TrustedValue("safe", "user")},
    )
    action = PlannedAction(
        "custom_tool",
        {"destination": Value("attacker", Provenance("document", TrustLevel.UNTRUSTED))},
    )
    decision = ref_monitor.evaluate(action, contract)
    assert decision.type == DecisionType.DENY
    assert "bound_argument_changed:destination" in decision.reasons


def test_matching_bound_value_is_still_denied_when_authority_provenance_is_untrusted():
    contract = TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    action = PlannedAction(
        "send_email",
        {
            "recipient": Value("alice@example.com", Provenance("document", TrustLevel.UNTRUSTED)),
            "body": Value("hello", Provenance("model", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )
    decision = monitor().evaluate(action, contract)
    assert decision.type == DecisionType.DENY
    assert "bound_argument_not_trusted:recipient" in decision.reasons


def test_denies_missing_capability_scope():
    contract = TaskContract(allowed_tools={"send_email"})
    action = PlannedAction(
        "send_email",
        {
            "recipient": TrustedValue("alice@example.com", "user"),
            "body": TrustedValue("hello"),
        },
    )
    decision = monitor().evaluate(action, contract)
    assert decision.type == DecisionType.DENY
    assert "missing_required_scope:email:send" in decision.reasons


def test_denies_secret_data_through_public_email_body():
    from vais import ConfidentialityLevel

    contract = TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    action = PlannedAction(
        "send_email",
        {
            "recipient": TrustedValue("alice@example.com", "user"),
            "body": TrustedValue(
                "API_KEY=secret",
                source="secret_store",
                confidentiality=ConfidentialityLevel.SECRET,
            ),
        },
    )
    decision = monitor().evaluate(action, contract)
    assert decision.type == DecisionType.DENY
    assert "confidentiality_exceeds_limit:body:secret>public" in decision.reasons
