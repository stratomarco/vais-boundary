"""Receipts and effect confidence (P1b-7): what is known about an effect beyond the decision.

Before P1b-7 an MCP effect was the request VAIS dispatched (LIM-046). A server that reported
delivering to attacker@evil.test still produced an effect naming the legitimate recipient, and
the verifier could not tell (review gap G1).
"""
from __future__ import annotations

import asyncio

import pytest

from vais import (
    ArgumentPolicy,
    Policy,
    ReferenceMonitor,
    TaskContract,
    ToolPolicy,
    TrustedValue,
    PlannedAction,
)
from vais.audit import AuditTrail
from vais.exceptions import PolicyValidationError
from vais.invariants import load_invariants
from vais.mcp import (
    MCPEffectMapping,
    MCPProfile,
    MCPProtectedClient,
    MCPReadBackReconciler,
    MCPReadBackSpec,
    MCPToolBinding,
    Reconciliation,
    acknowledge_effect,
    apply_reconciliation,
    load_mcp_profile,
)
from vais.sandbox import Effect, EffectConfidence, SandboxExecutor

RECIPIENT = "alice@example.com"
EMAIL = MCPEffectMapping("email_sent", {"recipient": "recipient", "body": "body"}, acknowledge={"recipient": "delivered_to"})
PROFILE = MCPProfile(bindings=(MCPToolBinding("mail", "send_email", "send_email", effect=EMAIL),))
POLICY = Policy(version=5, default_action="deny", tools={
    "send_email": ToolPolicy(allow=True, arguments={"recipient": ArgumentPolicy("trusted"), "body": ArgumentPolicy()})})
CONTRACT = TaskContract(allowed_tools={"send_email"}, granted_scopes=set(),
                        bound_arguments={("send_email", "recipient"): TrustedValue(RECIPIENT)},
                        principal_id="p", session_id="s", tenant_id="t", capability_id="c")
ACTION = PlannedAction("send_email", {"recipient": TrustedValue(RECIPIENT), "body": TrustedValue("hi")})


class Server:
    """An MCP server session that replies with whatever it is told to."""

    def __init__(self, reply=None, record=None, fail=False):
        self.reply, self.record, self.fail, self.calls = reply, record, fail, []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, dict(arguments or {})))
        if name == "get_message":
            if self.fail:
                raise ConnectionError("records unavailable")
            return self.record
        return self.reply


def _execute(server, reconcilers=None, audit=None):
    client = MCPProtectedClient(server_id="mail", session=server, profile=PROFILE, monitor=ReferenceMonitor(POLICY),
                                audit=audit, reconcilers=reconcilers)
    return asyncio.run(client.execute(ACTION, CONTRACT)).effect


def _effect(confidence=EffectConfidence.REQUESTED, fields=()):
    return Effect("email_sent", {"recipient": RECIPIENT}, confidence=confidence, contradicted_fields=fields)


# --- acknowledgement from the reply ---------------------------------------------------

def test_the_lying_server_is_now_contradicted():
    audit = AuditTrail()
    effect = _execute(Server(reply={"delivered_to": "attacker@evil.test"}), audit=audit)
    assert effect.confidence is EffectConfidence.CONTRADICTED
    assert effect.contradicted_fields == ("recipient",)
    assert effect.attributes["recipient"] == RECIPIENT  # the request, still recorded as requested
    observed = [e for e in audit.events if e.event_type == "effect_observed"][0]
    assert observed.details["confidence"] == "contradicted"
    assert "attacker@evil.test" not in audit.to_jsonl()  # names only, never values


def test_a_reply_repeating_the_effect_acknowledges_it_and_silence_leaves_it_requested():
    assert _execute(Server(reply={"delivered_to": RECIPIENT})).confidence is EffectConfidence.ACKNOWLEDGED
    assert _execute(Server(reply={"status": "ok"})).confidence is EffectConfidence.REQUESTED
    assert _execute(Server(reply="sent")).confidence is EffectConfidence.REQUESTED
    assert acknowledge_effect(_effect(), {}, {"delivered_to": "x"}).confidence is EffectConfidence.REQUESTED


# --- confirmation by read-back -----------------------------------------------------------

def _readback(records):
    return {"email_sent": MCPReadBackReconciler(records, "get_message", arguments={"id": "reply.message_id"},
                                                expect={"recipient": "to"})}


def test_a_read_back_from_the_system_of_record_confirms_or_contradicts():
    reply = {"delivered_to": RECIPIENT, "message_id": "m-1"}
    records = Server(record={"to": RECIPIENT})
    assert _execute(Server(reply=reply), _readback(records)).confidence is EffectConfidence.CONFIRMED
    assert records.calls == [("get_message", {"id": "m-1"})]

    # The executing server repeats the request, and the record says otherwise.
    lying = _execute(Server(reply=reply), _readback(Server(record={"to": "attacker@evil.test"})))
    assert (lying.confidence, lying.contradicted_fields) == (EffectConfidence.CONTRADICTED, ("recipient",))


def test_a_read_back_that_cannot_tell_or_fails_changes_nothing():
    reply = {"delivered_to": RECIPIENT, "message_id": "m-1"}
    assert _execute(Server(reply=reply), _readback(Server(record={"subject": "x"}))).confidence is EffectConfidence.ACKNOWLEDGED
    assert _execute(Server(reply={"delivered_to": RECIPIENT}), _readback(Server(record={"to": RECIPIENT}))).confidence \
        is EffectConfidence.ACKNOWLEDGED  # no message_id in the reply, so nothing to look up
    audit = AuditTrail()
    failed = _execute(Server(reply=reply), _readback(Server(fail=True)), audit=audit)
    assert failed.confidence is EffectConfidence.ACKNOWLEDGED
    assert [e.details["error"] for e in audit.events if e.event_type == "reconciliation_failed"] == ["ConnectionError"]


def test_a_contradiction_always_wins():
    confirmed = Reconciliation(EffectConfidence.CONFIRMED)
    contradicted = _effect(EffectConfidence.CONTRADICTED, ("recipient",))
    assert apply_reconciliation(contradicted, confirmed).confidence is EffectConfidence.CONTRADICTED
    with pytest.raises(ValueError):
        Reconciliation(EffectConfidence.ACKNOWLEDGED)
    with pytest.raises(ValueError):
        _effect(EffectConfidence.CONTRADICTED)  # a contradiction must name its fields
    with pytest.raises(ValueError):
        _effect(EffectConfidence.REQUESTED, ("recipient",))


def test_the_sandbox_performs_its_effects_so_they_are_confirmed():
    effect = SandboxExecutor().execute(ACTION)
    assert effect.confidence is EffectConfidence.CONFIRMED
    assert Effect("x", {}).confidence is EffectConfidence.REQUESTED  # nothing claims more by default


# --- VERIFY ----------------------------------------------------------------------------------

def test_verify_requires_the_level_asked_for_and_reports_what_each_verdict_rests_on(tmp_path):
    path = tmp_path / "inv.yaml"
    path.write_text("invariants:\n  - id: mail_confirmed\n    type: effect_confidence\n    effect: email_sent\n"
                    "    min_confidence: confirmed\n  - id: payments_confirmed\n    type: effect_confidence\n"
                    "    effect: payment_sent\n    min_confidence: acknowledged\n", encoding="utf-8")
    engine = load_invariants(path)
    effects = [_effect(EffectConfidence.CONFIRMED), _effect(EffectConfidence.ACKNOWLEDGED),
               _effect(EffectConfidence.CONTRADICTED, ("recipient",))]
    assert [v.reason for v in engine.evaluate(effects, CONTRACT)] == [
        "effect_confidence_below:acknowledged<confirmed", "effect_contradicted:recipient"]
    assert engine.verdict_basis(effects) == {"mail_confirmed": "contradicted", "payments_confirmed": "no_effects"}
    assert engine.verdict_basis(effects[:2]) == {"mail_confirmed": "acknowledged", "payments_confirmed": "no_effects"}

    path.write_text("invariants:\n  - id: x\n    type: effect_confidence\n    effect: e\n    min_confidence: requested\n",
                    encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_invariants(path)


# --- the profile ------------------------------------------------------------------------------

def test_the_profile_declares_acknowledgement_and_read_back(tmp_path):
    path = tmp_path / "profile.yaml"
    body = """version: 1
servers:
  mail:
    tools:
      send_email:
        canonical_tool: send_email
        effect:
          kind: email_sent
          argument_fields: {recipient: recipient}
          acknowledge: {recipient: delivered_to}
          confirm: {server: records, tool: get_message, arguments: {id: reply.message_id}, expect: {recipient: to}}
"""
    path.write_text(body, encoding="utf-8")
    effect = load_mcp_profile(path).bindings[0].effect
    assert dict(effect.acknowledge) == {"recipient": "delivered_to"}
    assert effect.confirm == MCPReadBackSpec("records", "get_message", {"id": "reply.message_id"}, {"recipient": "to"})

    for bad in (body.replace("reply.message_id", "message_id"), body.replace("expect: {recipient: to}", "expect: {}"),
                body.replace("acknowledge: {recipient:", "acknowledge: {subject:")):
        path.write_text(bad, encoding="utf-8")
        with pytest.raises(PolicyValidationError):
            load_mcp_profile(path)
