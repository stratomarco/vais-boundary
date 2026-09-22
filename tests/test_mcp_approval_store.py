"""Consume-once approvals on the MCP path (FIND-049), and what still holds without them.

Before rc12 ``MCPProtectedClient`` took no ``ApprovalStore`` and called the monitor
without one. The monitor then fell back to the contract's approved fingerprints,
which never consume, so one approval authorized the same MCP call every time it was
proposed. Found while answering an external reviewer's question about authority
freshness, reproduced with three identical calls all allowed and dispatched.

The first two tests fail if the client stops forwarding its store to the monitor.
The last one asserts the limitation that remains (LIM-044), so it stays visible.
"""
from __future__ import annotations

import asyncio

from vais import (
    ArgumentPolicy,
    ConfidentialityLevel,
    MCPCallState,
    MCPEffectMapping,
    MCPProfile,
    MCPProtectedClient,
    MCPResultPolicy,
    MCPToolBinding,
    PlannedAction,
    Policy,
    ReferenceMonitor,
    TaskContract,
    ToolPolicy,
    TrustedValue,
)
from vais.approvals import ApprovalStore


class RecordingSession:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments or {}))
        return {"sent": True}


def _policy() -> Policy:
    return Policy(
        version=3,
        default_action="deny",
        tools={
            "send_email": ToolPolicy(
                allow=True,
                required_scope="email:send",
                exact_approval_required=True,
                arguments={
                    "recipient": ArgumentPolicy(trust_required="trusted"),
                    "body": ArgumentPolicy(max_confidentiality=ConfidentialityLevel.INTERNAL),
                },
            )
        },
    )


def _profile() -> MCPProfile:
    return MCPProfile(
        (
            MCPToolBinding(
                server_id="ops",
                tool_name="send_email",
                canonical_tool="send_email",
                result_policy=MCPResultPolicy(ConfidentialityLevel.INTERNAL),
                effect=MCPEffectMapping("email_sent", {"recipient": "recipient", "body": "body"}),
            ),
        )
    )


def _contract(session_id: str = "s1") -> TaskContract:
    return TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", source="user")},
        principal_id="p1",
        session_id=session_id,
        tenant_id="t1",
        capability_id="c1",
    )


def _action(contract: TaskContract) -> PlannedAction:
    return PlannedAction(
        "send_email",
        {
            "recipient": contract.bound_arguments[("send_email", "recipient")],
            "body": TrustedValue("incident summary", source="application",
                                 confidentiality=ConfidentialityLevel.INTERNAL),
        },
    )


def _client(session, store=None) -> MCPProtectedClient:
    return MCPProtectedClient(
        server_id="ops", session=session, profile=_profile(),
        monitor=ReferenceMonitor(_policy()), approval_store=store,
    )


def _run(client, action, contract, times):
    return [asyncio.run(client.execute(action, contract)) for _ in range(times)]


def test_store_approval_is_consumed_once_on_the_mcp_path():
    contract = _contract()
    action = _action(contract)
    store = ApprovalStore()
    store.grant(action, contract)
    session = RecordingSession()

    records = _run(_client(session, store), action, contract, 3)

    assert [r.decision.type.value for r in records] == ["allow", "require_approval", "require_approval"]
    assert [r.call_state for r in records] == [
        MCPCallState.OBSERVED, MCPCallState.NOT_CALLED, MCPCallState.NOT_CALLED,
    ]
    assert len(session.calls) == 1


def test_store_approval_is_scoped_to_its_session_on_the_mcp_path():
    granted_for = _contract("s1")
    action = _action(granted_for)
    store = ApprovalStore()
    store.grant(action, granted_for)
    session = RecordingSession()

    other_session = _contract("s2")
    record = asyncio.run(_client(session, store).execute(action, other_session))

    assert record.decision.type.value == "require_approval"
    assert session.calls == []


def test_consumption_on_the_mcp_path_persists_across_restart(tmp_path):
    path = tmp_path / "approvals.json"
    contract = _contract()
    action = _action(contract)
    ApprovalStore(path).grant(action, contract)
    first = RecordingSession()
    assert asyncio.run(_client(first, ApprovalStore(path)).execute(action, contract)).decision.type.value == "allow"

    second = RecordingSession()
    record = asyncio.run(_client(second, ApprovalStore(path)).execute(action, contract))

    assert record.decision.type.value == "require_approval"
    assert second.calls == []


def test_limitation_contract_held_approval_is_reusable_without_a_store():
    # LIM-044. Without a store, an approval carried in the contract authorizes the
    # exact action for as long as the contract is in use, on both enforcement paths.
    # Consume-once needs an ApprovalStore; a stateful monitor (roadmap P1b-3) is the
    # planned fix. If this starts failing, the limitation has closed: update LIM-044.
    contract = _contract().with_approved_action(_action(_contract()))
    action = _action(contract)
    session = RecordingSession()

    records = _run(_client(session), action, contract, 3)

    assert [r.decision.type.value for r in records] == ["allow", "allow", "allow"]
    assert len(session.calls) == 3
