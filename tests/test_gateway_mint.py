"""Authority an application creates during a session, carried by the gateway (DEC-064, LIM-068).

An operator can declare in the MCP profile that a tool's result is authority for named
arguments of other tools. After an observed call the value is trusted for those arguments,
in that session only, and only when an argument is exactly equal to it.
"""
from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.approvals import ApprovalStore
from vais.exceptions import PolicyValidationError
from vais.gateway import ContractRegistry, Gateway, GatewayOutcomeKind, token_digest
from vais.mcp import MCPMintSpec, MCPProfile, MCPResultPolicy, MCPToolBinding, load_mcp_profile
from vais.models import ConfidentialityLevel

TOKEN, OTHER = "token-alice", "token-bob"
MINT = MCPMintSpec("artifact_id", (("ops.send", "artifact_id"),))
PROFILE = MCPProfile((
    MCPToolBinding("ops", "build", "ops.build", MCPResultPolicy(ConfidentialityLevel.PUBLIC), mints=(MINT,)),
    MCPToolBinding("ops", "send", "ops.send"),
))
POLICY = Policy(version=3, default_action="deny", tools={
    "ops.build": ToolPolicy(True, {"incident": ArgumentPolicy()}),
    "ops.send": ToolPolicy(True, {"artifact_id": ArgumentPolicy("trusted")}),
})


class Upstream:
    def __init__(self, reply=None):
        self.reply = {"artifact_id": "a-1"} if reply is None else reply
        self.calls = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, dict(arguments or {})))
        return self.reply if name == "build" else {"status": "sent"}


def _contract(directory, token, session, extra=""):
    (directory / f"{session}.yaml").write_text(
        f"version: 1\ntoken_sha256: {token_digest(token)}\nprincipal_id: alice\nsession_id: {session}\n"
        f"tenant_id: acme\ncapability_id: root\nallowed_tools: [ops.build, ops.send]\n{extra}", encoding="utf-8")


@pytest.fixture
def world(tmp_path):
    (tmp_path / "contracts").mkdir()
    _contract(tmp_path / "contracts", TOKEN, "s-1")
    _contract(tmp_path / "contracts", OTHER, "s-2")
    return tmp_path


def _gateway(world, upstream=None, *, state=False, policy=POLICY, profile=PROFILE):
    return Gateway(profile=profile, monitor=ReferenceMonitor(policy), registry=ContractRegistry(world / "contracts"),
                   sessions={"ops": upstream or Upstream()}, approval_store=ApprovalStore(),
                   pending_dir=world / "pending", state_dir=world / "state" if state else None)


def _call(gateway, name, arguments, token=TOKEN):
    return asyncio.run(gateway.call(token, name, arguments)).kind


ALLOWED, DENIED = GatewayOutcomeKind.ALLOWED, GatewayOutcomeKind.DENIED


def test_a_minted_value_is_authority_for_its_target_and_only_that_value(world):
    gateway = _gateway(world)
    assert _call(gateway, "ops.send", {"artifact_id": "a-1"}) is DENIED  # nothing minted yet
    assert _call(gateway, "ops.build", {"incident": "INC-1"}) is ALLOWED
    assert _call(gateway, "ops.send", {"artifact_id": "a-1"}) is ALLOWED
    assert _call(gateway, "ops.send", {"artifact_id": "a-2"}) is DENIED


def test_a_minted_value_belongs_to_its_session(world):
    gateway = _gateway(world)
    _call(gateway, "ops.build", {"incident": "INC-1"})
    assert _call(gateway, "ops.send", {"artifact_id": "a-1"}, token=OTHER) is DENIED


def test_a_contract_binding_still_wins_over_a_minted_value(world):
    _contract(world / "contracts", TOKEN, "s-1", "bound_arguments: {ops.send: {artifact_id: fixed}}\n")
    gateway = _gateway(world)
    _call(gateway, "ops.build", {"incident": "INC-1"})
    assert _call(gateway, "ops.send", {"artifact_id": "a-1"}) is DENIED
    assert _call(gateway, "ops.send", {"artifact_id": "fixed"}) is ALLOWED


def test_a_denied_call_mints_nothing(world):
    policy = Policy(version=3, default_action="deny", tools={"ops.send": POLICY.tools["ops.send"]})
    gateway = _gateway(world, policy=policy)
    assert _call(gateway, "ops.build", {"incident": "INC-1"}) is DENIED
    assert _call(gateway, "ops.send", {"artifact_id": "a-1"}) is DENIED


@pytest.mark.parametrize("reply", [{"other": "a-1"}, {"artifact_id": True}, {"artifact_id": 1.5},
                                   {"artifact_id": {"nested": "a-1"}}, "a-1"])
def test_a_result_without_a_usable_value_mints_nothing_and_says_so(world, reply):
    gateway = _gateway(world, Upstream(reply))
    _call(gateway, "ops.build", {"incident": "INC-1"})
    assert "authority_not_minted" in [e.event_type for e in gateway.audit.events]
    assert _call(gateway, "ops.send", {"artifact_id": "a-1"}) is DENIED


def test_the_audit_records_a_digest_of_the_value_not_the_value(world):
    gateway = _gateway(world)
    _call(gateway, "ops.build", {"incident": "INC-1"})
    (event,) = [e for e in gateway.audit.events if e.event_type == "authority_minted"]
    assert event.details["targets"] == ("ops.send.artifact_id",)
    assert event.details["value_sha256"] == hashlib.sha256(json.dumps("a-1").encode()).hexdigest()
    assert "a-1" not in gateway.audit.to_jsonl()


def test_a_whole_scalar_result_can_be_minted(world):
    profile = MCPProfile((
        MCPToolBinding("ops", "build", "ops.build", mints=(MCPMintSpec(None, (("ops.send", "artifact_id"),)),)),
        MCPToolBinding("ops", "send", "ops.send"),
    ))
    gateway = _gateway(world, Upstream("pub-7"), profile=profile)
    _call(gateway, "ops.build", {"incident": "INC-1"})
    assert _call(gateway, "ops.send", {"artifact_id": "pub-7"}) is ALLOWED


def test_minted_values_survive_a_restart_with_a_state_directory_and_not_without(world):
    _call(_gateway(world, state=True), "ops.build", {"incident": "INC-1"})
    assert _call(_gateway(world, state=True), "ops.send", {"artifact_id": "a-1"}) is ALLOWED
    _call(_gateway(world), "ops.build", {"incident": "INC-1"})
    assert _call(_gateway(world), "ops.send", {"artifact_id": "a-1"}) is DENIED


# --- the profile ------------------------------------------------------------------------------

PROFILE_YAML = """\
version: 1
servers:
  status:
    tools:
      build_public_update:
        canonical_tool: status.build_public_update
        mints:
          - from: {source}
            to: [email.send_public_update.artifact_id]
  email:
    tools:
      send_public_update:
        canonical_tool: email.send_public_update
"""


def test_a_profile_declares_mints_with_dotted_canonical_tool_names(tmp_path):
    for source, field in (("result", None), ("result.artifact_id", "artifact_id")):
        path = tmp_path / "profile.yaml"
        path.write_text(PROFILE_YAML.format(source=source), encoding="utf-8")
        binding = load_mcp_profile(path).by_canonical_tool("status.build_public_update")
        assert binding.mints == (MCPMintSpec(field, (("email.send_public_update", "artifact_id"),)),)


@pytest.mark.parametrize("change", [
    ("from: {source}", "from: reply"),
    ("from: {source}", "from: result.a.b"),
    ("to: [email.send_public_update.artifact_id]", "to: []"),
    ("to: [email.send_public_update.artifact_id]", "to: [nowhere.artifact_id]"),
    ("to: [email.send_public_update.artifact_id]", "to: [artifact_id]"),
    ("to: [email.send_public_update.artifact_id]",
     "to: [email.send_public_update.artifact_id, email.send_public_update.artifact_id]"),
])
def test_a_malformed_mint_is_refused(tmp_path, change):
    path = tmp_path / "profile.yaml"
    path.write_text(PROFILE_YAML.replace(*change).format(source="result"), encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_mcp_profile(path)


def test_nothing_is_minted_for_a_tool_the_session_may_not_use(world):
    # Least authority, and what the library does: it binds a minted value only for allowed
    # tools. The replay found the gateway otherwise labelled such arguments more trusted.
    (world / "contracts" / "s-1.yaml").write_text(
        (world / "contracts" / "s-1.yaml").read_text(encoding="utf-8").replace("[ops.build, ops.send]", "[ops.build]"),
        encoding="utf-8")
    gateway = _gateway(world)
    _call(gateway, "ops.build", {"incident": "INC-1"})
    (event,) = [e for e in gateway.audit.events if e.event_type == "authority_not_minted"]
    assert event.details["reason"] == "no_allowed_target"
    assert gateway._state(gateway.registry.lookup(TOKEN)).context.minted == {}
