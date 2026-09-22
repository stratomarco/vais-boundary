"""Audit events identify which action was decided, and for whom (rc12, G8).

Before rc12 an authorization event recorded the tool name and the *names* of the
arguments. The chain could prove that a payment was allowed but not which payment or
for which session, and the MCP client wrote no audit at all. Both enforcement paths
now record the action fingerprint and the contract identity. Neither records an
argument value, so the change adds identity without adding secrets.
"""
from __future__ import annotations

import asyncio

from vais import (
    AuditTrail,
    MCPEffectMapping,
    MCPProfile,
    MCPProtectedClient,
    MCPToolBinding,
    PlannedAction,
    Policy,
    ProtectedExecutor,
    ReferenceMonitor,
    SandboxExecutor,
    TaskContract,
    ToolPolicy,
    TrustedValue,
    action_fingerprint,
)
from vais.models import MAX_SECURITY_DEPTH

SECRET_BODY = "VAIS_TEST_CANARY_DO_NOT_EXFILTRATE"
IDENTITY = {"principal_id": "p1", "session_id": "s1", "tenant_id": "t1", "capability_id": "c1"}


def _policy() -> Policy:
    return Policy(version=4, default_action="deny",
                  tools={"send_email": ToolPolicy(allow=True, reject_undeclared_arguments=False)})


def _contract() -> TaskContract:
    return TaskContract(allowed_tools={"send_email"}, **IDENTITY)


def _action() -> PlannedAction:
    return PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com"),
                                        "body": TrustedValue(SECRET_BODY)})


def _assert_identifies(event, action):
    assert event.details["action_fingerprint"] == action_fingerprint(action)
    for key, value in IDENTITY.items():
        assert event.details[key] == value
    assert event.details["arguments"] == ("body", "recipient")


def _assert_no_values(audit: AuditTrail):
    exported = audit.to_jsonl()
    assert SECRET_BODY not in exported
    assert "alice@example.com" not in exported


def test_protected_executor_audit_identifies_the_action_and_session():
    audit = AuditTrail()
    action = _action()
    ProtectedExecutor(ReferenceMonitor(_policy()), SandboxExecutor(), audit=audit).run([action], _contract())

    decision, effect = audit.events
    assert decision.event_type == "authorization_decision"
    _assert_identifies(decision, action)
    assert effect.event_type == "effect_observed"
    assert effect.details["action_fingerprint"] == action_fingerprint(action)
    _assert_no_values(audit)
    assert audit.verify()


class _Session:
    def __init__(self, fail: bool = False):
        self.fail = fail

    async def call_tool(self, name, arguments=None):
        if self.fail:
            raise TimeoutError("upstream said VAIS_TEST_CANARY_DO_NOT_EXFILTRATE")
        return {"ok": True}


def _mcp_client(audit: AuditTrail, fail: bool = False) -> MCPProtectedClient:
    profile = MCPProfile((MCPToolBinding("ops", "send_email", "send_email",
                                         effect=MCPEffectMapping("email_sent", {"recipient": "recipient"})),))
    return MCPProtectedClient(server_id="ops", session=_Session(fail), profile=profile,
                              monitor=ReferenceMonitor(_policy()), audit=audit)


def test_mcp_client_audit_identifies_the_action_and_session():
    audit = AuditTrail()
    action = _action()
    asyncio.run(_mcp_client(audit).execute(action, _contract()))

    decision, effect = audit.events
    assert decision.event_type == "authorization_decision"
    assert decision.decision == "allow"
    _assert_identifies(decision, action)
    assert effect.event_type == "effect_observed"
    assert effect.details["action_fingerprint"] == action_fingerprint(action)
    _assert_no_values(audit)
    assert audit.verify()


def test_mcp_client_audits_denials_before_the_monitor():
    audit = AuditTrail()
    unbound = PlannedAction("shell_exec", {"command": TrustedValue("id")})
    asyncio.run(_mcp_client(audit).execute(unbound, _contract()))

    (event,) = audit.events
    assert event.decision == "deny"
    assert event.reasons == ("mcp_binding_missing:shell_exec",)
    assert event.details["action_fingerprint"] == action_fingerprint(unbound)
    assert event.details["session_id"] == "s1"


def test_mcp_indeterminate_call_is_audited_by_class_only():
    audit = AuditTrail()
    action = _action()
    asyncio.run(_mcp_client(audit, fail=True).execute(action, _contract()))

    decision, outcome = audit.events
    assert decision.decision == "allow"
    assert outcome.event_type == "effect_indeterminate"
    assert outcome.details == {"error": "TimeoutError", "action_fingerprint": action_fingerprint(action)}
    _assert_no_values(audit)


def test_unfingerprintable_action_is_still_audited_as_a_denial():
    # Nested to exactly the accepted depth, so the Value constructs but the fingerprint
    # payload wraps it two levels deeper and fails (see test_fingerprint_recursion).
    # The audit helper must record None rather than raise, or the denial goes unaudited.
    data: object = "leaf"
    for _ in range(MAX_SECURITY_DEPTH):
        data = [data]
    action = PlannedAction("deep_tool", {"payload": TrustedValue(data)})
    policy = Policy(version=3, default_action="deny",
                    tools={"deep_tool": ToolPolicy(allow=True, exact_approval_required=True)})
    audit = AuditTrail()

    ProtectedExecutor(ReferenceMonitor(policy), SandboxExecutor(), audit=audit).run(
        [action], TaskContract(allowed_tools={"deep_tool"}, **IDENTITY)
    )

    (event,) = audit.events
    assert event.decision == "deny"
    assert event.reasons == ("action_not_fingerprintable",)
    assert event.details["action_fingerprint"] is None
    assert event.details["session_id"] == "s1"
