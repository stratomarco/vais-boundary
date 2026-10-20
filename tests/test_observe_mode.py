"""Observe-only mode (1.0 track, step 5): the gateway decides as if enforcing, audits the
decision as ``would_<decision>``, forwards the call anyway, and stops by itself.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from vais import ApprovalPolicy, ArgumentPolicy, ConfidentialityLevel, Policy, ReferenceMonitor, ToolPolicy
from vais.approvals import ApprovalStore
from vais.audit import verify_jsonl
from vais.exceptions import PolicyValidationError
from vais.gateway import OBSERVE_MAX_SECONDS, ContractRegistry, Gateway, GatewayOutcomeKind, token_digest
from vais.gateway_server import load_gateway_config
from vais.mcp import MCPEffectMapping, MCPProfile, MCPResultPolicy, MCPToolBinding

TOKEN = "agent-token-observe"
NOW = 1_800_000_000.0
DAY = 24 * 3600

PROFILE = MCPProfile(bindings=(
    MCPToolBinding("ops", "get_incident", "mcp:ops:get_incident", MCPResultPolicy(ConfidentialityLevel.INTERNAL)),
    MCPToolBinding("ops", "send_email", "mcp:ops:send_email",
                   effect=MCPEffectMapping("email_sent", {"recipient": "recipient"})),
    MCPToolBinding("ops", "pay", "mcp:ops:pay"),
))

POLICY = Policy(version=5, default_action="deny", tools={
    "mcp:ops:get_incident": ToolPolicy(allow=True, arguments={"incident_id": ArgumentPolicy("trusted")}),
    "mcp:ops:send_email": ToolPolicy(allow=True, arguments={"recipient": ArgumentPolicy("trusted"),
                                                            "body": ArgumentPolicy()}, max_calls=2),
    "mcp:ops:pay": ToolPolicy(allow=True, arguments={"payee": ArgumentPolicy("trusted"), "amount": ArgumentPolicy()},
                              approval=ApprovalPolicy("amount", 100)),
})

CONTRACT = f"""\
version: 1
token_sha256: {token_digest(TOKEN)}
principal_id: alice
session_id: s-1
tenant_id: acme
capability_id: root
allowed_tools: [mcp:ops:get_incident, mcp:ops:send_email, mcp:ops:pay]
bound_arguments:
  mcp:ops:get_incident: {{incident_id: INC-1}}
  mcp:ops:send_email: {{recipient: ir-team@acme.test}}
  mcp:ops:pay: {{payee: vendor-9}}
"""


class Upstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, dict(arguments or {})))
        return {"ok": True}


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


def make(tmp_path: Path, *, observe_until: float | None, clock: Clock | None = None):
    contracts = tmp_path / "contracts"
    contracts.mkdir(exist_ok=True)
    (contracts / "alice.yaml").write_text(CONTRACT, encoding="utf-8")
    upstream, clock = Upstream(), clock or Clock()
    gateway = Gateway(profile=PROFILE, monitor=ReferenceMonitor(POLICY), registry=ContractRegistry(contracts),
                      sessions={"ops": upstream}, approval_store=ApprovalStore(tmp_path / "approvals.json"),
                      pending_dir=tmp_path / "pending", audit_path=tmp_path / "audit.jsonl",
                      observe_until=observe_until, clock=clock)
    return gateway, upstream, clock


def call(gateway, name, arguments):
    return asyncio.run(gateway.call(TOKEN, name, arguments))


def events(gateway, kind):
    return [e for e in (json.loads(line) for line in gateway.audit.to_jsonl().splitlines()) if e["event_type"] == kind]


def test_a_call_enforcement_would_deny_is_forwarded_and_audited(tmp_path):
    gateway, upstream, _ = make(tmp_path, observe_until=NOW + DAY)
    outcome = call(gateway, "ops.send_email", {"recipient": "attacker@evil.test", "body": "x"})
    assert outcome.kind is GatewayOutcomeKind.ALLOWED
    assert upstream.calls == [("send_email", {"recipient": "attacker@evil.test", "body": "x"})]
    [decision] = events(gateway, "observe_only_decision")
    assert decision["decision"] == "would_deny" and decision["reasons"]
    assert [e["details"]["call_state"] for e in events(gateway, "observe_only_dispatch")] == ["observed"]


def test_an_approval_is_neither_requested_nor_consumed(tmp_path):
    gateway, upstream, _ = make(tmp_path, observe_until=NOW + DAY)
    outcome = call(gateway, "ops.pay", {"payee": "vendor-9", "amount": 500})
    assert outcome.kind is GatewayOutcomeKind.ALLOWED and len(upstream.calls) == 1
    assert events(gateway, "observe_only_decision")[0]["decision"] == "would_require_approval"
    assert not (tmp_path / "pending").exists()


def test_observing_leaves_an_operators_grant_for_enforcement(tmp_path):
    from vais.gateway import label_agent_action
    gateway, upstream, clock = make(tmp_path, observe_until=NOW + DAY)
    contract = gateway.registry.lookup(TOKEN)
    arguments = {"payee": "vendor-9", "amount": 500}
    gateway.approval_store.grant(label_agent_action("mcp:ops:pay", arguments, contract, ConfidentialityLevel.PUBLIC), contract)
    call(gateway, "ops.pay", arguments)
    assert events(gateway, "observe_only_decision")[0]["decision"] == "would_require_approval"
    clock.now = NOW + DAY  # enforcing now: the grant is still there to use
    assert call(gateway, "ops.pay", arguments).kind is GatewayOutcomeKind.ALLOWED


def test_only_calls_enforcement_would_allow_count_against_limits(tmp_path):
    gateway, upstream, _ = make(tmp_path, observe_until=NOW + DAY)
    bound = {"recipient": "ir-team@acme.test", "body": "x"}
    call(gateway, "ops.send_email", {"recipient": "attacker@evil.test", "body": "x"})  # would deny: not counted
    for _ in range(3):
        call(gateway, "ops.send_email", bound)
    decisions = [e["decision"] for e in events(gateway, "observe_only_decision")]
    assert decisions == ["would_deny", "would_allow", "would_allow", "would_deny"]  # max_calls 2
    assert len(upstream.calls) == 4


def test_the_mode_ends_by_itself(tmp_path):
    gateway, upstream, clock = make(tmp_path, observe_until=NOW + DAY)
    assert gateway.observing()
    clock.now = NOW + DAY
    assert not gateway.observing()
    outcome = call(gateway, "ops.send_email", {"recipient": "attacker@evil.test", "body": "x"})
    assert outcome.kind is GatewayOutcomeKind.DENIED and upstream.calls == []
    assert events(gateway, "observe_only_decision") == []


def test_it_cannot_be_configured_for_more_than_fourteen_days(tmp_path):
    make(tmp_path, observe_until=NOW + OBSERVE_MAX_SECONDS)
    with pytest.raises(PolicyValidationError, match="14 days"):
        make(tmp_path, observe_until=NOW + OBSERVE_MAX_SECONDS + 1)
    assert OBSERVE_MAX_SECONDS == 14 * DAY


def test_a_past_expiry_enforces_from_the_start(tmp_path):
    gateway, upstream, _ = make(tmp_path, observe_until=NOW - 1)
    assert not gateway.observing()
    assert call(gateway, "ops.send_email", {"recipient": "attacker@evil.test", "body": "x"}).kind is GatewayOutcomeKind.DENIED
    assert events(gateway, "observe_only_configured")[0]["details"]["active"] is False


def test_authentication_and_the_contract_still_apply(tmp_path):
    gateway, upstream, _ = make(tmp_path, observe_until=NOW + DAY)
    assert asyncio.run(gateway.call("not-a-token", "ops.get_incident", {"incident_id": "INC-1"})).kind \
        is GatewayOutcomeKind.UNAUTHENTICATED
    assert call(gateway, "ops.restart", {}).kind is GatewayOutcomeKind.DENIED
    assert upstream.calls == []


def test_the_audit_chain_still_verifies(tmp_path):
    gateway, _, _ = make(tmp_path, observe_until=NOW + DAY)
    call(gateway, "ops.send_email", {"recipient": "attacker@evil.test", "body": "x"})
    assert verify_jsonl((tmp_path / "audit.jsonl").read_text(encoding="utf-8")).ok


# --- configuration: observe_until exists only in version 2 ---------------------------------

SAMPLE = Path(__file__).resolve().parent / "data" / "formats-1.0" / "gateway" / "gateway.yaml"


def _config(tmp_path: Path, version: int, extra: str = "") -> Path:
    for name in ("policy.yaml", "profile.yaml"):
        (tmp_path / name).write_text((SAMPLE.parent / name).read_text(encoding="utf-8"), encoding="utf-8")
    text = SAMPLE.read_text(encoding="utf-8").replace("version: 1", f"version: {version}", 1)
    path = tmp_path / "gateway.yaml"
    path.write_text(text + extra, encoding="utf-8")
    return path


def test_version_1_rejects_observe_until(tmp_path):
    with pytest.raises(PolicyValidationError, match="observe_until"):
        load_gateway_config(_config(tmp_path, 1, "observe_until: 2026-11-01T00:00:00Z\n"))


@pytest.mark.parametrize("value", ["2026-11-01T00:00:00Z", '"2026-11-01T00:00:00Z"', '"2026-11-01T01:00:00+01:00"'])
def test_version_2_accepts_a_time_with_a_timezone(tmp_path, value):
    config = load_gateway_config(_config(tmp_path, 2, f"observe_until: {value}\n"))
    assert config.observe_until == datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp()


@pytest.mark.parametrize("value", ["2026-11-01", '"2026-11-01T00:00:00"', "tomorrow", "1800000000"])
def test_version_2_rejects_anything_without_a_date_time_and_timezone(tmp_path, value):
    with pytest.raises(PolicyValidationError, match="observe_until"):
        load_gateway_config(_config(tmp_path, 2, f"observe_until: {value}\n"))


def test_version_2_without_observe_until_enforces(tmp_path):
    assert load_gateway_config(_config(tmp_path, 2)).observe_until is None


def test_other_versions_are_rejected(tmp_path):
    with pytest.raises(PolicyValidationError, match="version"):
        load_gateway_config(_config(tmp_path, 3))
