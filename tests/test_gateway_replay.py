"""The gateway decides no more permissively than the library on the reference traces.

``vais.gateway_replay`` sends recorded library-path traces through a real ``Gateway``. On
every trace the deterministic reference targets produce, the gateway is never looser, and it
is stricter for exactly one known reason. A mutant gateway that trusts the agent's arguments
is caught, so the comparison can fail.
"""
from __future__ import annotations

import asyncio

import pytest

import vais.gateway as gateway_module
import vais.gateway_replay as replay
from vais.models import PlannedAction, TrustLevel, TrustedValue
from vais.reference_agent import (
    DeterministicReferenceTarget,
    ReferenceAgentRunner,
    ReferenceMode,
    SelectiveReferenceTarget,
)

# Without a declared mint, the gateway denied the public-update sends the library allowed:
# the library binds the declassifier's artifact id into the contract, and an operator's
# contract file cannot (LIM-068). The replay profile declares that mint (DEC-064).
WITHOUT_MINT = {
    ("email.send_public_update", "allow", "deny"),
    ("slack.send_public_update", "allow", "deny"),
}


def _reference_records() -> list[dict]:
    runner, records = ReferenceAgentRunner(), []
    for target in (DeterministicReferenceTarget(), SelectiveReferenceTarget()):
        for workflow in replay.workflows_by_id().values():
            result = asyncio.run(runner.run_workflow(workflow, target, mode=ReferenceMode.PROTECTED))
            records.append({"protected_result": result.to_dict()})
    return records


@pytest.fixture(scope="module")
def records() -> list[dict]:
    return _reference_records()


def test_with_the_declassifier_mint_the_gateway_decides_exactly_as_the_library(records):
    summary = replay.summarize(c for *_, c in replay.replay_records(records, parts=("protected_result",)))
    assert summary["traces"] == len(records) == summary["traces_identical"]
    assert set(summary["decisions"]) == {"same"}
    # Labels may still be more confidential at the gateway; none is less trusted or looser.
    assert set(summary["argument_labels"]) <= {"same", "gateway_stricter"}
    assert summary["trust_lost_by_argument"] == {}


def test_without_the_mint_the_sends_are_denied_as_before(records, monkeypatch):
    unminted = replay.MCPProfile(tuple(
        replay.MCPToolBinding(b.server_id, b.tool_name, b.canonical_tool, b.result_policy, b.effect)
        for b in replay.REPLAY_PROFILE.bindings))
    monkeypatch.setattr(replay, "INCIDENT_REPLAY", replay.replace(replay.INCIDENT_REPLAY, profile=unminted))
    summary = replay.summarize(c for *_, c in replay.replay_records(records, parts=("protected_result",)))
    assert "gateway_looser" not in summary["decisions"]
    assert {(d["tool"], d["library"], d["gateway"]) for d in summary["divergences"]} == WITHOUT_MINT
    assert set(summary["divergence_causes"]) == {replay.MINTED_AUTHORITY}
    assert set(summary["trust_lost_by_argument"]) == {"email.send_public_update.artifact_id",
                                                      "slack.send_public_update.artifact_id"}


def test_a_gateway_that_trusted_the_agent_would_be_caught(records, monkeypatch):
    def trusting(tool, arguments, contract, context_level, context_trust=TrustLevel.DERIVED_UNTRUSTED, minted=None):
        return PlannedAction(tool, {name: TrustedValue(data, source="agent") for name, data in arguments.items()})

    monkeypatch.setattr(gateway_module, "label_agent_action", trusting)
    monkeypatch.setattr(replay, "label_agent_action", trusting)
    summary = replay.summarize(c for *_, c in replay.replay_records(records, parts=("protected_result",)))
    assert summary["decisions"].get("gateway_looser", 0) > 0
    assert summary["divergence_causes"].get("unexplained", 0) > 0
    assert summary["argument_labels"].get("gateway_looser", 0) > 0


def test_a_reused_contract_approval_is_explained_and_nothing_else_is(tmp_path):
    # The library path has no store or ledger, so a contract approval can authorize the same
    # action again (LIM-044); the gateway allows it once (DEC-060). The replay names that cause.
    workflow = next(w for w in replay.workflows_by_id().values() if w.approved_restart_service)
    runner = ReferenceAgentRunner()
    result = asyncio.run(runner.run_workflow(workflow, DeterministicReferenceTarget(), mode=ReferenceMode.PROTECTED))
    trace = result.to_dict()["trace"]
    restart = next(s for s in trace if s["action"] and s["action"]["tool"] == "production.restart_service"
                   and s["decision"]["type"] == "allow")
    repeated = [*trace, {**restart, "index": 99, "phase": "agent_turn_9"}]
    comparison = asyncio.run(replay.replay_trace(workflow, repeated, tmp_path))
    divergence = comparison.first_divergence
    assert divergence is not None and divergence.index == 99
    assert divergence.cause == replay.CONTRACT_APPROVAL_SINGLE_USE
