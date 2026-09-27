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

# Why the gateway is stricter than the library on the reference application. Until FIND-062
# was fixed, a contract-held restart approval was a second reason.
KNOWN_STRICTER = {
    # The library mints the declassifier's artifact id into the contract as a trusted binding;
    # an operator's contract file cannot, so the gateway labels it model output (LIM-068).
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


def test_the_gateway_is_never_looser_and_stricter_only_for_known_reasons(records):
    summary = replay.summarize(c for *_, c in replay.replay_records(records, parts=("protected_result",)))
    assert summary["traces"] == len(records)
    assert "gateway_looser" not in summary["decisions"]
    assert set(summary["argument_labels"]) <= {"same", "gateway_stricter"}
    assert summary["decisions"]["same"] > 0
    # Only the minted artifact id ever loses trust; every other stricter label is the same
    # trust at a higher confidentiality.
    assert set(summary["trust_lost_by_argument"]) <= {"email.send_public_update.artifact_id",
                                                      "slack.send_public_update.artifact_id"}
    assert {(d["tool"], d["library"], d["gateway"]) for d in summary["divergences"]} == KNOWN_STRICTER
    assert set(summary["divergence_causes"]) == {replay.MINTED_AUTHORITY}
    for d in summary["divergences"]:
        if d["tool"].endswith("send_public_update"):
            assert "artifact_id" in d["labels_changed"].split(",")


def test_a_gateway_that_trusted_the_agent_would_be_caught(records, monkeypatch):
    def trusting(tool, arguments, contract, context_level, context_trust=TrustLevel.DERIVED_UNTRUSTED):
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
