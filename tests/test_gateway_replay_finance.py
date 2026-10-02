"""The gateway replay for the accounts-payable application (P1b-11, FIND-073)."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import pytest

import vais.gateway_replay as replay
from vais.gateway import load_gateway_contract
from vais.models import TrustedValue

FIXTURE = json.loads((Path(__file__).parent / "data" / "finance_same_turn_mint_trace.json").read_text(encoding="utf-8"))


def _replay(trace, baseline=FIXTURE["reference_baseline_version"], tmp_path=None):
    app = replay.replay_application("accounts-payable")
    workflow = app.workflows()[FIXTURE["workflow_id"]]
    return asyncio.run(replay.replay_trace(workflow, trace, tmp_path, app, baseline))


def test_a_value_minted_earlier_in_the_same_turn_is_the_one_known_looser_cause(tmp_path):
    """granite read the vendor record and paid with its bank account in one planned turn. The
    library labelled the turn before running it and refused; the gateway labels each call on
    arrival and held the 7,200.00 payment for a human's approval."""
    comparison = _replay(FIXTURE["trace"], tmp_path=tmp_path)
    (step,) = [s for s in comparison.steps if s.decision != "same"]
    assert (step.tool, step.library_decision, step.gateway_decision) == ("payments.pay", "deny", "require_approval")
    assert step.cause == replay.SAME_TURN_MINT
    assert step.labels["bank_account_id"] == "gateway_looser"


def test_a_value_that_is_not_the_minted_one_is_refused_by_both(tmp_path):
    trace = copy.deepcopy(FIXTURE["trace"])
    trace[4]["action"]["arguments"]["bank_account_id"]["data"] = "ACCT-EVIL-777"
    comparison = _replay(trace, tmp_path=tmp_path)
    assert comparison.first_divergence is None


def test_the_cause_is_not_claimed_when_the_mint_came_from_an_earlier_turn(tmp_path):
    trace = copy.deepcopy(FIXTURE["trace"])
    for step in trace[1:4]:
        step["phase"] = "agent_turn_0"  # the vendor record read a turn earlier
    comparison = _replay(trace, tmp_path=tmp_path)
    (step,) = [s for s in comparison.steps if s.decision != "same"]
    assert step.decision == "gateway_looser" and step.cause == "unexplained"


def test_contract_files_carry_the_session_rules(tmp_path):
    app = replay.replay_application("accounts-payable")
    workflow = app.workflows()["attack-21"]
    path = tmp_path / "c.yaml"
    replay._contract_file(path, "t", app.contract_for(workflow, "1.4"), session_id="s", capability_id="c")
    _, loaded = load_gateway_contract(path)
    def plain(rules):  # a contract file's values come from "contract", the library's from "user"
        return {key: ([v.data for v in allowed.values], allowed.once) for key, allowed in rules.items()}

    assert plain(loaded.allowed_values) == plain(workflow.contract.allowed_values)
    assert loaded.budgets == workflow.contract.budgets
    assert loaded.value_budgets == workflow.contract.value_budgets


@pytest.mark.parametrize("baseline, rules", [("1.1", (False, False, False)), ("1.2", (True, True, False)),
                                             ("1.3", (True, True, False)), ("1.4", (True, True, True))])
def test_the_gateway_gets_the_contract_the_trace_was_recorded_under(baseline, rules):
    app = replay.replay_application("accounts-payable")
    workflow = app.workflows()["attack-21"]
    contract = app.contract_for(workflow, baseline)
    assert (bool(contract.allowed_values), bool(contract.budgets), bool(contract.value_budgets)) == rules
    invoice_rule = app.policy_for(workflow, baseline).tools["payments.pay"].arguments["invoice_id"]
    assert (invoice_rule.trust_required == "trusted") == (baseline != "1.1")


def test_other_tasks_are_unchanged_across_baselines():
    app = replay.replay_application("accounts-payable")
    for workflow in app.workflows().values():
        if workflow.id in {"attack-21", "control-21", "clean-06"}:
            continue
        assert all(app.contract_for(workflow, b) == workflow.contract for b in ("1.1", "1.2", "1.3", "1.4"))


def test_an_unknown_application_is_refused():
    with pytest.raises(ValueError):
        replay.replay_application("payroll")


def test_records_without_an_application_replay_as_incident_response():
    assert replay.replay_application(None) is replay.INCIDENT_REPLAY


def _scripted_records() -> list[dict]:
    from vais.reference_agent import DeterministicReferenceTarget, ReferenceAgentRunner, ReferenceMode

    runner, records = ReferenceAgentRunner(), []
    for workflow in replay.replay_application("accounts-payable").workflows().values():
        result = asyncio.run(runner.run_workflow(workflow, DeterministicReferenceTarget(), mode=ReferenceMode.PROTECTED))
        records.append({"reference_application": "accounts-payable", "reference_baseline_version": "1.4",
                        "protected_result": result.to_dict()})
    return records


def test_the_scripted_agents_runs_decide_identically_at_the_gateway():
    """Every story's protected run, with its setup reads, mints, payments and remittances."""
    records = _scripted_records()
    tools = {s["action"]["tool"] for r in records for s in r["protected_result"]["trace"] if s.get("action")}
    phases = {s["phase"] for r in records for s in r["protected_result"]["trace"]}
    assert {"vendors.get", "payments.pay", "payments.build_remittance", "email.send_remittance"} <= tools
    assert "trusted_retrieval" in phases
    summary = replay.summarize(c for *_, c in replay.replay_records(records, parts=("protected_result",)))
    assert summary["traces"] == len(records) == summary["traces_identical"]
    assert set(summary["decisions"]) == {"same"}
    assert summary["trust_lost_by_argument"] == {}


def test_without_the_mints_the_gateway_refuses_what_the_library_allowed(monkeypatch):
    app = replay.replay_application("accounts-payable")
    unminted = replay.MCPProfile(tuple(replay.replace(b, mints=()) for b in app.profile.bindings))
    monkeypatch.setattr(replay, "_finance_replay", lambda: replay.replace(app, profile=unminted))
    summary = replay.summarize(c for *_, c in replay.replay_records(_scripted_records(), parts=("protected_result",)))
    assert "gateway_looser" not in summary["decisions"]
    assert {d["tool"] for d in summary["divergences"]} >= {"payments.pay"}
    assert set(summary["divergence_causes"]) == {replay.MINTED_AUTHORITY}


def test_the_replay_recognises_the_applications_own_refusal():
    """An unknown remittance advice is refused by the application after the monitor allowed the
    call; the replay must count that as the library allowing it. It never occurred in the
    recorded traces, since the monitor refuses an unminted advice id first."""
    from vais.models import Decision, DecisionType, PlannedAction
    from vais.reference_agent import ReferenceMode
    from vais.reference_finance import _execute_owned

    class Environment:
        public_artifacts: dict = {}

        def decide(self, *args, **kwargs):
            return Decision(DecisionType.ALLOW)

    action = PlannedAction("email.send_remittance", {"recipient": TrustedValue("ap@northwind.test", source="u"),
                                                     "advice_id": TrustedValue("RA-NOPE", source="u")})
    record = asyncio.run(_execute_owned(Environment(), action, None, ReferenceMode.PROTECTED))
    (reason,) = record.decision.reasons
    assert reason.startswith(replay.replay_application("accounts-payable").application_refusals)


def test_a_looser_label_that_did_not_come_from_a_mint_is_unexplained(tmp_path, monkeypatch):
    original = replay.label_agent_action

    def from_the_contract(tool, arguments, contract, *args, **kwargs):
        planned = original(tool, arguments, contract, *args, **kwargs)
        if tool != "payments.pay":
            return planned
        value = planned.arguments["bank_account_id"]
        relabelled = {**planned.arguments, "bank_account_id": TrustedValue(value.data, source="contract")}
        return replay.replace(planned, arguments=relabelled)

    monkeypatch.setattr(replay, "label_agent_action", from_the_contract)
    (step,) = [s for s in _replay(FIXTURE["trace"], tmp_path=tmp_path).steps if s.decision != "same"]
    assert step.decision == "gateway_looser" and step.cause == "unexplained"
