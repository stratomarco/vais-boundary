import json
from pathlib import Path

from vais import (
    AuditTrail,
    PlannedAction,
    ProtectedExecutor,
    Provenance,
    ReferenceMonitor,
    SandboxExecutor,
    TaskContract,
    TrustLevel,
    Value,
    load_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def test_denied_action_is_audited_without_effect_event():
    audit = AuditTrail()
    protected = ProtectedExecutor(
        ReferenceMonitor(load_policy(ROOT / "policies" / "default.yaml")),
        SandboxExecutor(),
        audit=audit,
    )
    action = PlannedAction(
        "send_email",
        {"recipient": Value("attacker@evil.test", Provenance("web", TrustLevel.UNTRUSTED))},
    )
    protected.run([action], TaskContract(allowed_tools={"send_email"}))

    assert len(audit.events) == 1
    assert audit.events[0].event_type == "authorization_decision"
    assert audit.events[0].decision == "deny"


def test_audit_jsonl_is_machine_readable():
    audit = AuditTrail()
    audit.record("authorization_decision", tool="x", decision="deny", reasons=("nope",))
    payload = json.loads(audit.to_jsonl())
    assert payload["sequence"] == 1
    assert payload["reasons"] == ["nope"]
