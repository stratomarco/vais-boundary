"""A hung upstream is bounded, and what it did stays unknown (LIM-040).

Before rc14 nothing on the MCP path had a timeout, so a tool server or a read-back that never
answered hung the caller. With call_timeout a call that runs out of time is INDETERMINATE:
it was dispatched, so its effect is unknown, and it is neither a denial nor scored as
defended. A read-back that runs out of time leaves the effect's confidence where it was.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.audit import AuditTrail
from vais.exceptions import PolicyValidationError
from vais.gateway import ContractRegistry, Gateway, GatewayOutcomeKind
from vais.gateway_server import load_gateway_config
from vais.mcp import (MCPCallState, MCPEffectMapping, MCPProfile, MCPProtectedClient, MCPReadBackReconciler,
                      MCPToolBinding)
from vais.models import PlannedAction, TaskContract, TrustedValue
from vais.approvals import ApprovalStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_gateway import POLICY as GATEWAY_POLICY, PROFILE as GATEWAY_PROFILE, TOKEN, _write_contract  # noqa: E402

PROFILE = MCPProfile((MCPToolBinding("ops", "send", "ops.send",
                                     effect=MCPEffectMapping("sent", {"to": "to"}, acknowledge={"to": "to"})),))
POLICY = Policy(version=3, default_action="deny", tools={"ops.send": ToolPolicy(True, {"to": ArgumentPolicy("trusted")})})
CONTRACT = TaskContract(allowed_tools={"ops.send"})
ACTION = PlannedAction("ops.send", {"to": TrustedValue("ops@acme.test", source="user")})


class Upstream:
    def __init__(self, delay: float, reply=None):
        self.delay, self.reply, self.calls = delay, reply or {"to": "ops@acme.test"}, 0

    async def call_tool(self, name, arguments=None):
        self.calls += 1
        await asyncio.sleep(self.delay)
        return self.reply


def _client(session, *, timeout=None, reconcilers=None, audit=None):
    return MCPProtectedClient(server_id="ops", session=session, profile=PROFILE, monitor=ReferenceMonitor(POLICY),
                              audit=audit, reconcilers=reconcilers, call_timeout=timeout)


def test_a_hung_call_is_indeterminate_not_denied_and_not_an_effect():
    audit = AuditTrail()
    upstream = Upstream(delay=30)
    record = asyncio.run(_client(upstream, timeout=0.05, audit=audit).execute(ACTION, CONTRACT))
    assert record.call_state is MCPCallState.INDETERMINATE
    assert record.decision.type.value == "allow" and record.effect is None
    assert record.error == "TimeoutError" and upstream.calls == 1
    assert [e.event_type for e in audit.events][-1] == "effect_indeterminate"


def test_a_call_inside_the_timeout_is_observed():
    record = asyncio.run(_client(Upstream(delay=0), timeout=5).execute(ACTION, CONTRACT))
    assert record.call_state is MCPCallState.OBSERVED and record.effect.confidence.value == "acknowledged"


def test_a_hung_read_back_leaves_the_confidence_and_is_audited():
    audit = AuditTrail()
    records = Upstream(delay=30, reply={"to": "ops@acme.test"})
    reconciler = MCPReadBackReconciler(records, "get", arguments={"to": "effect.to"}, expect={"to": "to"})
    record = asyncio.run(_client(Upstream(delay=0), timeout=0.05, audit=audit,
                                 reconcilers={"sent": reconciler}).execute(ACTION, CONTRACT))
    assert record.call_state is MCPCallState.OBSERVED
    assert record.effect.confidence.value == "acknowledged"  # not confirmed, not contradicted
    assert "reconciliation_failed" in [e.event_type for e in audit.events]


@pytest.mark.parametrize("bad", [0, -1, float("inf"), float("nan"), True, "5"])
def test_a_timeout_must_be_a_positive_finite_number(bad):
    with pytest.raises(ValueError):
        _client(Upstream(0), timeout=bad)


def test_the_gateway_reports_a_hung_upstream_as_indeterminate(tmp_path):
    (tmp_path / "contracts").mkdir()
    _write_contract(tmp_path / "contracts")
    gateway = Gateway(profile=GATEWAY_PROFILE, monitor=ReferenceMonitor(GATEWAY_POLICY),
                      registry=ContractRegistry(tmp_path / "contracts"), sessions={"ops": Upstream(delay=30)},
                      approval_store=ApprovalStore(), pending_dir=tmp_path / "pending", call_timeout=0.05)
    outcome = asyncio.run(gateway.call(TOKEN, "ops.send_email", {"recipient": "ir-team@acme.test", "body": "s"}))
    assert outcome.kind is GatewayOutcomeKind.INDETERMINATE


@pytest.mark.parametrize("value, ok", [("60", True), ("0.5", True), ("0", False), ("-3", False), ("true", False), ("'60'", False)])
def test_the_gateway_configuration_takes_a_call_timeout(tmp_path, value, ok):
    path = tmp_path / "gateway.yaml"
    path.write_text("version: 1\npolicy: p.yaml\nprofile: m.yaml\ncontracts: c/\napprovals: a.json\npending: q/\n"
                    f"audit: log.jsonl\ncall_timeout: {value}\nupstreams: {{ops: {{stdio: {{command: python}}}}}}\n",
                    encoding="utf-8")
    if ok:
        assert load_gateway_config(path).call_timeout == float(value)
    else:
        with pytest.raises(PolicyValidationError):
            load_gateway_config(path)
