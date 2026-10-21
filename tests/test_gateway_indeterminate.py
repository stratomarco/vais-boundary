"""Consequential calls, idempotency keys and correlation in the gateway (DEC-074, FIND-078).

Integration step 2 (docs/workflow-integration-inventory.md), gaps R5, R6 and R8. The backend
here is the accounts-payable sandbox's own store (examples/ap_sandbox), reached in process
through a stand-in for the gateway's upstream session, so idempotency, receipts and faults
behave as the sandbox's do. tests/test_ap_sandbox.py covers the same backend over MCP.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

import pytest

from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.approvals import ApprovalStore
from vais.audit import AuditTrail
from vais.cli import main as cli
from vais.exceptions import PolicyValidationError
from vais.gateway import (
    INDETERMINATE_DIR,
    ContractRegistry,
    Gateway,
    GatewayOutcomeKind,
    resolve_indeterminate_call,
    token_digest,
)
from vais.gateway_server import agent_schema, configuration_digests, load_gateway_config
from vais.mcp import (MCPEffectMapping, MCPProfile, MCPReadBackSpec, MCPToolBinding, idempotency_key,
                      load_mcp_profile)
from vais.models import PlannedAction, TaskContract, TrustedValue

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(EXAMPLES))
from ap_sandbox.store import FaultBeforeCommit, SandboxError, Store, init_database  # noqa: E402

SEED = json.loads((EXAMPLES / "ap_sandbox" / "seed.json").read_text(encoding="utf-8"))
TOKEN, OTHER = "ap-clerk-token-1", "ap-clerk-token-2"
PAY = {"vendor_id": "V-100", "bank_account_id": "ACCT-NW-001", "invoice_id": "INV-1001", "amount": "1250.00"}
PAY_2 = {**PAY, "invoice_id": "INV-1002", "amount": "3400.00"}
FIELDS = {"vendor_id": "vendor_id", "bank_account_id": "bank_account_id", "invoice_id": "invoice_id",
          "amount": "amount", "idempotency_key": "idempotency_key"}
CONFIRM = MCPReadBackSpec("ap", "find_payment", {"idempotency_key": "effect.idempotency_key"},
                          {"invoice_id": "invoice_id", "amount": "amount"})


def _binding(*, key: bool = True, confirm: bool = True, consequential: bool = True) -> MCPToolBinding:
    fields = FIELDS if key else {k: v for k, v in FIELDS.items() if k != "idempotency_key"}
    return MCPToolBinding("ap", "pay", "mcp:ap:pay", effect=MCPEffectMapping(
        "payment", fields, acknowledge={"invoice_id": "invoice_id"}, confirm=CONFIRM if confirm else None),
        consequential=consequential, idempotency_argument="idempotency_key" if key else None, receipt="receipt")


def _policy(max_calls: int) -> Policy:
    return Policy(version=5, default_action="deny", tools={"mcp:ap:pay": ToolPolicy(True, {
        "vendor_id": ArgumentPolicy("trusted"), "bank_account_id": ArgumentPolicy("trusted"),
        "invoice_id": ArgumentPolicy(), "amount": ArgumentPolicy()}, max_calls=max_calls)})


CONTRACT = """\
version: 1
token_sha256: {digest}
principal_id: clerk-1
session_id: {session}
tenant_id: acme
capability_id: pay-batch
allowed_tools: [mcp:ap:pay]
bound_arguments:
  mcp:ap:pay: {{vendor_id: V-100, bank_account_id: ACCT-NW-001}}
"""


class ErrorReply:
    """An MCP tool error: a reply, not an exception."""

    isError = True
    structuredContent = None

    def __init__(self, text: str) -> None:
        self.content = [type("Text", (), {"text": text})()]


class StoreSession:
    """The sandbox store as the gateway's upstream session, acting out its armed faults."""

    def __init__(self, store: Store) -> None:
        self.store, self.sent = store, []

    @property
    def payments_sent(self):
        return [arguments for name, arguments in self.sent if name == "pay"]

    async def call_tool(self, name, arguments=None):
        arguments = dict(arguments or {})
        self.sent.append((name, arguments))
        try:
            if name == "find_payment":
                return self.store.find_payment(**arguments)
            outcome = getattr(self.store, name)(**arguments)
        except FaultBeforeCommit:
            return ErrorReply("internal error")
        except SandboxError as exc:
            return ErrorReply(str(exc))
        if outcome.fault is not None:
            if outcome.fault.mode == "hang_after_commit":
                await asyncio.sleep(outcome.fault.seconds)
            elif outcome.fault.mode == "crash_after_commit":
                raise ConnectionResetError("upstream exited")
            elif outcome.fault.mode == "error_after_commit":
                return ErrorReply("internal error")
        return outcome.reply


class Setup:
    def __init__(self, tmp_path: Path, binding: MCPToolBinding, *, max_calls: int = 1) -> None:
        self.tmp = tmp_path
        init_database(tmp_path / "ap.sqlite3", SEED, "sandbox-test-key-0123456789")
        self.store = Store(tmp_path / "ap.sqlite3")
        self.session = StoreSession(self.store)
        contracts = tmp_path / "contracts"
        contracts.mkdir()
        for token, session in ((TOKEN, "run-1"), (OTHER, "run-2")):
            (contracts / f"{session}.yaml").write_text(
                CONTRACT.format(digest=token_digest(token), session=session), encoding="utf-8")
        self.pending = tmp_path / "pending"
        self.audit = AuditTrail()
        self.gateway = Gateway(profile=MCPProfile((binding,), version=2), monitor=ReferenceMonitor(_policy(max_calls)),
                               registry=ContractRegistry(contracts), sessions={"ap": self.session},
                               approval_store=ApprovalStore(tmp_path / "approvals.json"), pending_dir=self.pending,
                               audit=self.audit, state_dir=tmp_path / "state", call_timeout=0.3,
                               configuration={"policy_sha256": "0" * 64})

    def call(self, arguments=PAY, token=TOKEN):
        return asyncio.run(self.gateway.call(token, "ap.pay", arguments))

    def events(self, kind):
        return [e for e in self.audit.events if e.event_type == kind]

    def records(self):
        directory = self.pending / INDETERMINATE_DIR
        return sorted(p.name for p in directory.glob("*.json")) if directory.is_dir() else []

    def last_call_id(self):
        return self.events("indeterminate_recorded")[-1].details["call_id"]


# --- the profile ----------------------------------------------------------------------------

PROFILE_V2 = """\
version: 2
servers:
  ap:
    tools:
      pay:
        canonical_tool: mcp:ap:pay
        consequential: true
        idempotency_argument: idempotency_key
        receipt: receipt
        effect:
          kind: payment
          argument_fields: {invoice_id: invoice_id, amount: amount, idempotency_key: idempotency_key}
          confirm: {server: ap, tool: find_payment, arguments: {idempotency_key: effect.idempotency_key}, expect: {invoice_id: invoice_id}}
      find_payment: {}
"""


def test_profile_version_2_adds_the_keys_and_version_1_keeps_rejecting_them(tmp_path):
    path = tmp_path / "profile.yaml"
    path.write_text(PROFILE_V2, encoding="utf-8")
    binding = load_mcp_profile(path).by_canonical_tool("mcp:ap:pay")
    assert binding.consequential and binding.idempotency_argument == "idempotency_key" and binding.receipt == "receipt"
    keys = ("consequential: true", "idempotency_argument: idempotency_key", "receipt: receipt")
    for key in keys:
        # One version 2 key at a time in a version 1 file.
        text = PROFILE_V2.replace("version: 2", "version: 1")
        for other in keys:
            if other != key:
                text = text.replace(f"        {other}\n", "")
        path.write_text(text, encoding="utf-8")
        with pytest.raises(PolicyValidationError, match=f"unknown field.*{key.partition(':')[0]}"):
            load_mcp_profile(path)
    path.write_text(PROFILE_V2.replace("consequential: true", "consequential: yes please"), encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="true or false"):
        load_mcp_profile(path)
    with pytest.raises(ValueError, match="profile version 2"):
        MCPProfile((_binding(),), version=1)


# --- R6: the idempotency key ------------------------------------------------------------------

def test_the_gateway_sends_a_key_it_derives_and_the_agent_never_sees_or_sets(tmp_path):
    setup = Setup(tmp_path, _binding())
    outcome = setup.call()
    assert outcome.kind is GatewayOutcomeKind.ALLOWED
    sent_key = setup.session.payments_sent[0]["idempotency_key"]
    contract = ContractRegistry(tmp_path / "contracts").lookup(TOKEN)
    action = PlannedAction("mcp:ap:pay", {k: TrustedValue(v, source="t") for k, v in PAY.items()})
    assert sent_key == idempotency_key(action, contract) and sent_key.startswith("vais-")
    assert setup.store.find_payment(sent_key)["invoice_id"] == "INV-1001"

    refused = setup.call({**PAY, "idempotency_key": sent_key})
    assert refused.kind is GatewayOutcomeKind.DENIED and len(setup.session.payments_sent) == 1
    assert setup.events("authorization_decision")[-1].reasons == ("reserved_argument:idempotency_key",)

    schema = {"type": "object", "properties": {"amount": {}, "idempotency_key": {}}, "required": ["amount", "idempotency_key"]}
    assert agent_schema(schema, _binding()) == {"type": "object", "properties": {"amount": {}}, "required": ["amount"]}
    assert agent_schema(schema, _binding(key=False)) == schema


def test_the_same_action_in_another_session_gets_another_key(tmp_path):
    setup = Setup(tmp_path, _binding())
    setup.call()
    setup.call(token=OTHER)
    first, second = (sent["idempotency_key"] for sent in setup.session.payments_sent)
    assert first != second and len(setup.store.list_payments()) == 2


# --- R8: correlation, configuration and receipts in the audit ----------------------------------

def test_every_event_of_a_call_carries_its_call_id_and_the_effect_its_receipt(tmp_path):
    setup = Setup(tmp_path, _binding())
    setup.call()
    assert setup.events("gateway_configuration")[0].details == {"policy_sha256": "0" * 64}
    call = setup.events("gateway_call")[0].details
    contract_file = tmp_path / "contracts" / "run-1.yaml"
    import hashlib
    assert call["contract_sha256"] == hashlib.sha256(contract_file.read_bytes()).hexdigest()
    call_id = call["call_id"]
    decision = setup.events("authorization_decision")[0].details
    effect = setup.events("effect_observed")[0].details
    assert decision["call_id"] == effect["call_id"] == call_id
    receipt = setup.store.list_receipts()[0]
    assert effect["receipt"]["receipt_id"] == receipt["receipt_id"] and effect["receipt"]["digest"] == receipt["digest"]
    assert len(effect["reply_sha256"]) == 64 and effect["confidence"] == "confirmed"
    assert effect["idempotency_key"] == receipt["idempotency_key"]


def test_configuration_digests_cover_the_files_the_gateway_runs_with():
    config = load_gateway_config(EXAMPLES / "gateway" / "gateway.yaml")
    digests = configuration_digests(config)
    assert set(digests) == {"vais_version", "policy_sha256", "profile_sha256", "configuration_sha256"}
    assert all(len(value) == 64 for key, value in digests.items() if key.endswith("sha256"))


# --- R5: error replies and lost replies --------------------------------------------------------

def test_an_error_reply_from_a_consequential_tool_is_indeterminate_and_recorded(tmp_path):
    setup = Setup(tmp_path, _binding())
    setup.store.arm_fault("pay", "error_after_commit")
    outcome = setup.call()
    assert outcome.kind is GatewayOutcomeKind.INDETERMINATE and not setup.events("effect_observed")
    assert setup.events("effect_indeterminate")[0].details["error"] == "tool_error"
    assert len(setup.records()) == 1 and len(setup.store.list_payments()) == 1  # the backend did pay


def test_an_error_reply_from_another_tool_is_still_observed_and_flagged(tmp_path):
    setup = Setup(tmp_path, _binding(consequential=False, key=False, confirm=False))
    setup.store.arm_fault("pay", "fail_before_commit")
    outcome = setup.call()
    assert outcome.kind is GatewayOutcomeKind.ALLOWED and setup.records() == []
    assert setup.events("effect_observed")[0].details["tool_error"] is True


@pytest.mark.parametrize("fault", ["hang_after_commit", "crash_after_commit", "error_after_commit"])
def test_the_exact_retry_with_a_key_is_paid_once_and_returns_the_payment(tmp_path, fault):
    # max_calls is 1: the retry is the same call, so the limit counts it once.
    setup = Setup(tmp_path, _binding())
    setup.store.arm_fault("pay", fault, seconds=5)
    assert setup.call().kind is GatewayOutcomeKind.INDETERMINATE
    retry = setup.call()
    assert retry.kind is GatewayOutcomeKind.ALLOWED and retry.result["replayed"] is True
    assert len(setup.store.list_payments()) == 1 and setup.records() == []
    settled = setup.events("indeterminate_resolved")[0].details
    assert settled["outcome"] == "superseded_by_retry" and settled["method"] == "retry"
    assert setup.call().kind is GatewayOutcomeKind.DENIED  # and a third is a new call, over the limit


def test_a_retry_counts_once_against_the_limit(tmp_path):
    setup = Setup(tmp_path, _binding(), max_calls=2)
    setup.store.arm_fault("pay", "hang_after_commit", seconds=5)
    setup.call()
    assert setup.call().kind is GatewayOutcomeKind.ALLOWED
    assert setup.call(PAY_2).kind is GatewayOutcomeKind.ALLOWED  # the second of two calls, not the third
    assert [p["invoice_id"] for p in setup.store.list_payments()] == ["INV-1001", "INV-1002"]


def test_a_retry_after_a_failure_before_commit_pays_once(tmp_path):
    setup = Setup(tmp_path, _binding())
    setup.store.arm_fault("pay", "fail_before_commit")
    assert setup.call().kind is GatewayOutcomeKind.INDETERMINATE and setup.store.list_payments() == []
    retry = setup.call()
    assert retry.kind is GatewayOutcomeKind.ALLOWED and retry.result["replayed"] is False
    assert len(setup.store.list_payments()) == 1


def test_another_call_waits_until_a_read_back_shows_the_first_happened(tmp_path):
    setup = Setup(tmp_path, _binding(), max_calls=2)
    setup.store.arm_fault("pay", "hang_after_commit", seconds=5)
    assert setup.call().kind is GatewayOutcomeKind.INDETERMINATE
    second = setup.call(PAY_2)
    assert second.kind is GatewayOutcomeKind.ALLOWED and setup.records() == []
    settled = setup.events("indeterminate_resolved")[0].details
    assert (settled["outcome"], settled["method"]) == ("happened", "read_back")
    assert [p["invoice_id"] for p in setup.store.list_payments()] == ["INV-1001", "INV-1002"]


def test_another_call_is_held_while_the_read_back_cannot_find_the_first(tmp_path):
    setup = Setup(tmp_path, _binding(), max_calls=2)
    setup.store.arm_fault("pay", "fail_before_commit")
    setup.call()
    held = setup.call(PAY_2)
    assert held.kind is GatewayOutcomeKind.DENIED and "reconciled first" in held.message
    assert setup.events("call_held")[0].reasons == ("indeterminate_unresolved",)
    assert setup.events("reconciliation_inconclusive") and setup.store.list_payments() == []
    assert len(setup.session.payments_sent) == 1


def test_without_a_key_even_the_exact_retry_waits_for_an_operator(tmp_path):
    setup = Setup(tmp_path, _binding(key=False, confirm=False))
    setup.store.arm_fault("pay", "fail_before_commit")
    setup.call()
    assert setup.call().kind is GatewayOutcomeKind.DENIED and len(setup.session.payments_sent) == 1
    resolve_indeterminate_call(setup.pending, setup.last_call_id(), "did_not_happen", by="ops-lead")
    retry = setup.call()
    assert retry.kind is GatewayOutcomeKind.ALLOWED and len(setup.store.list_payments()) == 1
    resolved = setup.events("indeterminate_resolved")
    assert [(e.details["outcome"], e.details["method"]) for e in resolved] == [
        ("did_not_happen", "operator"), ("superseded_by_retry", "retry")]
    assert resolved[0].details["by"] == "ops-lead" and setup.records() == []


def test_an_operator_saying_it_happened_releases_the_tool_and_the_limit_still_counts_it(tmp_path):
    setup = Setup(tmp_path, _binding(key=False, confirm=False))
    setup.store.arm_fault("pay", "hang_after_commit", seconds=5)
    setup.call()
    resolve_indeterminate_call(setup.pending, setup.last_call_id(), "happened", by="ops-lead")
    again = setup.call()
    assert again.kind is GatewayOutcomeKind.DENIED and len(setup.store.list_payments()) == 1
    assert setup.events("authorization_decision")[-1].reasons == ("call_limit_reached:mcp:ap:pay:1",)


def test_a_hold_is_per_session(tmp_path):
    setup = Setup(tmp_path, _binding(key=False, confirm=False))
    setup.store.arm_fault("pay", "fail_before_commit")
    setup.call()
    assert setup.call(token=OTHER).kind is GatewayOutcomeKind.ALLOWED


def test_holds_survive_a_restart_because_the_records_are_files(tmp_path):
    setup = Setup(tmp_path, _binding(key=False, confirm=False))
    setup.store.arm_fault("pay", "fail_before_commit")
    setup.call()
    restarted = Gateway(profile=setup.gateway.profile, monitor=setup.gateway.monitor, registry=setup.gateway.registry,
                        sessions={"ap": setup.session}, approval_store=setup.gateway.approval_store,
                        pending_dir=setup.pending, state_dir=tmp_path / "state")
    assert asyncio.run(restarted.call(TOKEN, "ap.pay", PAY)).kind is GatewayOutcomeKind.DENIED


def test_an_unreadable_record_holds_rather_than_guessing(tmp_path):
    setup = Setup(tmp_path, _binding(key=False, confirm=False))
    (setup.pending / INDETERMINATE_DIR).mkdir(parents=True)
    (setup.pending / INDETERMINATE_DIR / ("f" * 32 + ".json")).write_text("{not json", encoding="utf-8")
    held = setup.call()
    assert held.kind is GatewayOutcomeKind.DENIED and setup.session.sent == []
    assert setup.events("call_held")[0].reasons == ("indeterminate_record_unreadable",)


def test_resolutions_are_checked(tmp_path):
    setup = Setup(tmp_path, _binding(key=False, confirm=False))
    setup.store.arm_fault("pay", "fail_before_commit")
    setup.call()
    call_id = setup.last_call_id()
    with pytest.raises(PolicyValidationError, match="outcome"):
        resolve_indeterminate_call(setup.pending, call_id, "probably", by="ops")
    with pytest.raises(PolicyValidationError, match="name"):
        resolve_indeterminate_call(setup.pending, call_id, "happened", by=" ")
    with pytest.raises(PolicyValidationError, match="32 hexadecimal"):
        resolve_indeterminate_call(setup.pending, "../../etc/passwd", "happened", by="ops")
    with pytest.raises(PolicyValidationError, match="no unresolved call"):
        resolve_indeterminate_call(setup.pending, "0" * 32, "happened", by="ops")
    # A resolution file an operator mangled is reported and the hold stays.
    (setup.pending / INDETERMINATE_DIR / f"{call_id}.resolution.json").write_text('{"version": 1}', encoding="utf-8")
    assert setup.call().kind is GatewayOutcomeKind.DENIED
    assert setup.events("indeterminate_resolution_unreadable")


def test_the_operator_command(tmp_path, capsys):
    setup = Setup(tmp_path, _binding(key=False, confirm=False))
    setup.store.arm_fault("pay", "fail_before_commit")
    setup.call()
    config = tmp_path / "gateway.yaml"
    for name in ("policy.yaml", "profile.yaml"):
        (tmp_path / name).write_text("", encoding="utf-8")
    config.write_text("version: 1\npolicy: policy.yaml\nprofile: profile.yaml\ncontracts: contracts/\n"
                      "approvals: approvals.json\npending: pending/\naudit: audit.jsonl\nupstreams: {}\n", encoding="utf-8")
    assert cli(["gateway-resolve", "--config", str(config), setup.last_call_id(), "--did-not-happen", "--by", "ops"]) == 0
    assert "did_not_happen" in capsys.readouterr().out
    assert setup.call().kind is GatewayOutcomeKind.ALLOWED
