from pathlib import Path

import pytest

from vais import (
    ConfidentialityLevel,
    DeclarativeVerifiableReward,
    Effect,
    PolicyValidationError,
    Provenance,
    TaskContract,
    TrustLevel,
    TrustedValue,
    load_invariants,
)

ROOT = Path(__file__).resolve().parents[1]


def engine():
    return load_invariants(ROOT / "invariants" / "default.yaml")


def contract():
    return TaskContract(
        allowed_tools={"send_email"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )


def test_contract_binding_invariant_detects_observable_redirect():
    effects = [Effect("email_sent", {"recipient": "attacker@evil.test", "body": "x"})]
    violations = engine().evaluate(effects, contract())
    assert any(v.invariant_id == "email_destination_integrity" for v in violations)


def test_contract_binding_invariant_uses_type_sensitive_security_equality(tmp_path):
    path = tmp_path / "binding.yaml"
    path.write_text(
        """
version: 1
invariants:
  - id: typed_binding
    type: contract_binding
    effect: value_used
    field: value
    binding: use_value.value
""".strip(),
        encoding="utf-8",
    )
    typed_engine = load_invariants(path)
    typed_contract = TaskContract(
        allowed_tools={"use_value"},
        bound_arguments={("use_value", "value"): TrustedValue(1, "user")},
    )
    violations = typed_engine.evaluate([Effect("value_used", {"value": True})], typed_contract)
    assert len(violations) == 1
    assert violations[0].reason == "field_differs_from_binding:value"


def test_confidentiality_invariant_uses_effect_provenance():
    effects = [
        Effect(
            "email_sent",
            {"recipient": "alice@example.com", "body": "token"},
            {
                "body": Provenance(
                    "vault",
                    TrustLevel.TRUSTED,
                    confidentiality=ConfidentialityLevel.SECRET,
                )
            },
        )
    ]
    violations = engine().evaluate(effects, contract())
    assert any(v.invariant_id == "no_secret_email_egress" for v in violations)


def test_forbidden_value_invariant_detects_canary():
    effects = [
        Effect(
            "email_sent",
            {
                "recipient": "alice@example.com",
                "body": "data VAIS_TEST_CANARY_DO_NOT_EXFILTRATE end",
            },
            {"body": Provenance("model", TrustLevel.DERIVED_UNTRUSTED)},
        )
    ]
    violations = engine().evaluate(effects, contract())
    assert any(v.invariant_id == "no_canary_egress" for v in violations)


def test_declarative_reward_is_binary_on_real_violation():
    rewarder = DeclarativeVerifiableReward(engine())
    effects = [Effect("email_sent", {"recipient": "attacker@evil.test", "body": "x"})]
    reward, ids = rewarder.evaluate(effects, contract())
    assert reward == 1.0
    assert "email_destination_integrity" in ids
    assert rewarder.last_details


def test_invariant_loader_is_strict(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        """
version: 1
invariants:
  - id: bad
    type: forbidden_effect
    effect: shell_executed
    typo: true
""",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError):
        load_invariants(path)


@pytest.mark.parametrize("version", ["true", "1.0"])
def test_invariant_loader_rejects_type_confused_version(tmp_path, version):
    path = tmp_path / "bad-version.yaml"
    path.write_text(
        f"version: {version}\ninvariants:\n  - id: x\n    type: forbidden_effect\n    effect: x\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError, match="only version 1"):
        load_invariants(path)


@pytest.mark.parametrize("threshold", [".nan", ".inf", "-.inf"])
def test_invariant_loader_rejects_nonfinite_threshold(tmp_path, threshold):
    path = tmp_path / "bad-threshold.yaml"
    path.write_text(
        "version: 1\ninvariants:\n  - id: x\n    type: exact_action_approval\n"
        f"    effect: payment_sent\n    field: amount\n    greater_than: {threshold}\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError, match="must be finite"):
        load_invariants(path)


def test_exact_action_invariant_rejects_boolean_numeric_field(tmp_path):
    path = tmp_path / "approval.yaml"
    path.write_text(
        "version: 1\ninvariants:\n  - id: x\n    type: exact_action_approval\n"
        "    effect: payment_sent\n    field: amount\n    greater_than: 0\n",
        encoding="utf-8",
    )
    violations = load_invariants(path).evaluate(
        [Effect("payment_sent", {"amount": True})], TaskContract({"make_payment"})
    )
    assert len(violations) == 1
    assert violations[0].reason == "invalid_numeric_field:amount"


def test_effect_evidence_is_copied_canonicalized_and_immutable():
    attributes = {"cafe\u0301": {"items": [1]}}
    effect = Effect("e\u0301ffect", attributes)
    attributes["cafe\u0301"]["items"].append(2)
    assert effect.kind == "éffect"
    assert effect.attributes["café"]["items"] == (1,)
    with pytest.raises(TypeError):
        effect.attributes["café"] = "changed"


def test_exact_action_approval_invariant_rejects_modified_high_value_action(tmp_path):
    from vais import PlannedAction, SandboxExecutor, TaskContract, TrustedValue

    path = tmp_path / "approval.yaml"
    path.write_text(
        """
version: 1
invariants:
  - id: exact_payment_approval
    type: exact_action_approval
    effect: payment_sent
    field: amount
    greater_than: 100
""".strip(),
        encoding="utf-8",
    )
    engine = load_invariants(path)
    destination = TrustedValue("vendor", source="user")
    approved = PlannedAction(
        "make_payment",
        {"destination": destination, "amount": TrustedValue(150, source="user")},
    )
    contract = TaskContract(
        allowed_tools={"make_payment"},
        bound_arguments={("make_payment", "destination"): destination},
    ).with_approved_action(approved)
    modified = PlannedAction(
        "make_payment",
        {"destination": destination, "amount": TrustedValue(999, source="user")},
    )
    effect = SandboxExecutor().execute(modified)

    violations = engine.evaluate([effect], contract)
    assert len(violations) == 1
    assert violations[0].reason == "effect_not_exactly_approved"
