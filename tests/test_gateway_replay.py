"""The gateway decides no more permissively than the library on the reference traces.

``vais.gateway_replay`` sends recorded library-path traces through a real ``Gateway``. On
every trace the deterministic reference targets produce, the gateway is never looser, and it
is stricter for exactly two known reasons. A mutant gateway that trusts the agent's arguments
is caught, so the comparison can fail.
"""
from __future__ import annotations

import asyncio

import pytest

import vais.gateway as gateway_module
import vais.gateway_replay as replay
from vais.approvals import ApprovalStore
from vais.models import PlannedAction, Provenance, TrustLevel, TrustedValue, Value
from vais.monitor import ReferenceMonitor
from vais.reference_agent import (
    REFERENCE_POLICY,
    DeterministicReferenceTarget,
    ReferenceAgentRunner,
    ReferenceMode,
    SelectiveReferenceTarget,
    attack_workflows,
)

# The two reasons the gateway is stricter than the library on the reference application.
KNOWN_STRICTER = {
    # An approval held in the contract is ignored once an approval store is present (FIND-062).
    ("production.restart_service", "allow", "require_approval"),
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
    assert summary["argument_labels"].get("gateway_looser", 0) > 0


def test_an_approval_store_hides_contract_held_approvals():
    # FIND-062, recorded as found. If this starts failing, the contract's approvals are
    # honoured beside the store: update FIND-062, KNOWN_STRICTER and docs/gateway.md.
    workflow = next(w for w in attack_workflows() if w.approved_restart_service)
    action = PlannedAction("production.restart_service", {"service": Value(
        workflow.approved_restart_service, Provenance(source="model_output", trust=TrustLevel.DERIVED_UNTRUSTED))})
    monitor = ReferenceMonitor(REFERENCE_POLICY)
    assert monitor.evaluate(action, workflow.contract).type.value == "allow"
    assert monitor.evaluate(action, workflow.contract, ApprovalStore()).type.value == "require_approval"
