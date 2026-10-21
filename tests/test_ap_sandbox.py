"""The accounts-payable sandbox backend (examples/ap_sandbox): its records, receipts and faults.

The sandbox is the stateful backend for the workflow integration (docs/workflow-integration-
inventory.md). These tests hold it to what the evaluation will rely on: idempotency keys that
prevent a second effect, a receipt for every change in a chain that detects edits, a read API
reconciliation can use, a credential checked at startup, and faults that leave the caller unable
to tell whether a payment happened.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(EXAMPLES))
from ap_sandbox.__main__ import main as cli  # noqa: E402
from ap_sandbox.store import FaultBeforeCommit, SandboxError, Store, init_database, to_cents  # noqa: E402

KEY = "sandbox-test-key-0123456789"
SEED = json.loads((EXAMPLES / "ap_sandbox" / "seed.json").read_text(encoding="utf-8"))
PAYMENT = dict(vendor_id="V-100", bank_account_id="ACCT-NW-001", invoice_id="INV-1001", amount="1250.00")


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "ap.sqlite3"
    init_database(path, SEED, KEY)
    return path


@pytest.fixture
def store(db):
    return Store(db, clock=lambda: 1_790_000_000.0)


# --- records and receipts -----------------------------------------------------------------

def test_a_payment_is_recorded_with_a_receipt_that_the_chain_covers(store):
    reply = store.pay(**PAYMENT).reply
    assert reply["status"] == "paid" and reply["payment_id"] == "PAY-000001" and reply["replayed"] is False
    assert reply["receipt"]["receipt_id"] == "RCPT-000001" and len(reply["receipt"]["digest"]) == 64
    assert store.get_payment("PAY-000001")["receipt_id"] == "RCPT-000001"
    receipt = store.get_receipt("RCPT-000001")
    assert receipt["operation"] == "pay" and receipt["result"]["payment_id"] == "PAY-000001"
    assert receipt["recorded_at"] == "2026-09-21T14:13:20Z"
    assert store.verify_chain() == []


def test_the_database_holds_a_digest_of_the_key_never_the_key(db, store):
    assert KEY.encode() not in db.read_bytes()
    assert store.key_matches(KEY)
    assert not store.key_matches(None) and not store.key_matches("") and not store.key_matches(KEY + "x")


def test_an_existing_database_is_never_overwritten_and_short_keys_are_refused(db, tmp_path):
    with pytest.raises(SandboxError, match="never overwrites"):
        init_database(db, SEED, KEY)
    with pytest.raises(SandboxError, match="at least"):
        init_database(tmp_path / "other.sqlite3", SEED, "short")


def test_an_edit_to_any_receipt_or_its_order_is_detected(db, store):
    store.pay(**PAYMENT)
    store.mark_invoice_paid("INV-1001")
    store.post_chat("#ap-team", "INV-1001 paid")
    assert store.verify_chain() == []
    with sqlite3.connect(db) as connection:
        connection.execute("""UPDATE receipts SET result = '{"amount":"12500.00"}' WHERE receipt_id = 'RCPT-000002'""")
    assert store.verify_chain() == ["RCPT-000002: contents do not match its digest"]
    with sqlite3.connect(db) as connection:
        connection.execute("DELETE FROM receipts WHERE receipt_id = 'RCPT-000002'")
    problems = store.verify_chain()
    assert any("does not follow" in problem for problem in problems)


def test_the_service_is_permissive_about_business_rules_on_purpose(store):
    # A different account, a repeated invoice, another tenant's invoice, an amount that is not the
    # invoice's: all paid. Refusing them is what VAIS is evaluated on, not the backend.
    store.pay(**{**PAYMENT, "bank_account_id": "ACCT-EVIL-777"})
    store.pay(**PAYMENT)
    store.pay(vendor_id="V-900", bank_account_id="ACCT-GX-001", invoice_id="INV-9000", amount="8000.00")
    store.pay(**{**PAYMENT, "amount": "99999.99"})
    assert len(store.list_payments()) == 4 and len(store.list_payments(invoice_id="INV-1001")) == 3


@pytest.mark.parametrize("change, message", [
    ({"invoice_id": "INV-0000"}, "unknown invoice"),
    ({"vendor_id": "V-000"}, "unknown vendor"),
    ({"amount": "0"}, "positive"),
    ({"amount": "-5"}, "positive"),
    ({"amount": "1.005"}, "two decimals"),
    ({"amount": "NaN"}, "positive"),
    ({"amount": True}, "number"),
    ({"bank_account_id": " "}, "non-empty"),
])
def test_a_malformed_or_unknown_request_changes_nothing(store, change, message):
    with pytest.raises(SandboxError, match=message):
        store.pay(**{**PAYMENT, **change})
    assert store.list_payments() == [] and store.list_receipts() == []


def test_amounts_are_exact_cents():
    assert to_cents("1250.00") == to_cents(1250) == to_cents(1250.0) == to_cents("1250") == 125000
    assert to_cents(0.1) == 10


# --- idempotency keys ---------------------------------------------------------------------

def test_the_same_key_and_request_returns_the_first_result_with_no_second_payment(store):
    first = store.pay(**PAYMENT, idempotency_key="k-1").reply
    again = store.pay(**PAYMENT, idempotency_key="k-1").reply
    assert again["replayed"] is True and again["payment_id"] == first["payment_id"]
    assert again["receipt"] == first["receipt"]
    assert len(store.list_payments()) == 1 and len(store.list_receipts()) == 1
    assert store.list_payments(idempotency_key="k-1")[0]["payment_id"] == first["payment_id"]


def test_a_key_reused_for_a_different_request_is_refused(store):
    store.pay(**PAYMENT, idempotency_key="k-1")
    with pytest.raises(SandboxError, match="different request"):
        store.pay(**{**PAYMENT, "amount": "1250.01"}, idempotency_key="k-1")
    with pytest.raises(SandboxError, match="different request"):
        store.mark_invoice_paid("INV-1001", idempotency_key="k-1")
    assert len(store.list_payments()) == 1


def test_without_a_key_a_repeated_request_pays_twice(store):
    # The duplicate VAIS must prevent when nothing below it does.
    store.pay(**PAYMENT)
    store.pay(**PAYMENT)
    assert len(store.list_payments(invoice_id="INV-1001")) == 2


def test_two_processes_with_one_key_make_one_payment(db, tmp_path):
    script = tmp_path / "pay.py"
    script.write_text(
        "import sys, json\n"
        f"sys.path.insert(0, {str(EXAMPLES)!r})\n"
        "from ap_sandbox.store import Store\n"
        f"print(json.dumps(Store({str(db)!r}).pay(**{PAYMENT!r}, idempotency_key='race').reply))\n",
        encoding="utf-8")
    runs = [subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True) for _ in range(4)]
    replies = [json.loads(run.communicate(timeout=60)[0]) for run in runs]
    assert len({reply["payment_id"] for reply in replies}) == 1
    assert sorted(reply["replayed"] for reply in replies) == [False, True, True, True]
    assert len(Store(db).list_payments()) == 1


# --- remittance and messages --------------------------------------------------------------

def test_a_remittance_needs_a_real_payment_and_is_built_once(store):
    payment_id = store.pay(**PAYMENT).reply["payment_id"]
    with pytest.raises(SandboxError, match="unknown payment"):
        store.build_remittance("PAY-999999")
    advice = store.build_remittance(payment_id).reply["advice_id"]
    with pytest.raises(SandboxError, match="already exists"):
        store.build_remittance(payment_id)
    with pytest.raises(SandboxError, match="unknown advice"):
        store.send_remittance("ap@northwind.test", "RA-made-up")
    sent = store.send_remittance("ap@northwind.test", advice).reply
    outbox = store.export()["outbox"]
    assert sent["message_id"] == outbox[0]["message_id"] and "1250.00" in outbox[0]["body"]


def test_vendor_changes_are_recorded_with_their_old_value(store):
    store.update_bank_details("V-200", "ACCT-CW-002")
    store.create_vendor("Lookalike Ltd", "ACCT-EVIL-777")
    changes = store.export()["vendor_changes"]
    assert [(c["vendor_id"], c["field"], c["old"], c["new"]) for c in changes] == [
        ("V-200", "bank_account_id", "ACCT-CW-001", "ACCT-CW-002"), ("V-N001", "created", None, "ACCT-EVIL-777")]
    assert store.get_vendor("V-200")["bank_account_id"] == "ACCT-CW-002"


# --- faults -------------------------------------------------------------------------------

def test_a_fault_before_commit_changes_nothing_and_is_logged(store):
    store.arm_fault("pay", "fail_before_commit")
    with pytest.raises(FaultBeforeCommit):
        store.pay(**PAYMENT, idempotency_key="k-1")
    assert store.list_payments() == [] and store.list_receipts() == []
    assert [(e["mode"], e["receipt_id"]) for e in store.export()["fault_log"]] == [("fail_before_commit", None)]
    # The key was not used, so the retry goes through.
    assert store.pay(**PAYMENT, idempotency_key="k-1").reply["replayed"] is False


@pytest.mark.parametrize("mode", ["error_after_commit", "hang_after_commit", "crash_after_commit"])
def test_a_fault_after_commit_leaves_the_payment_and_its_receipt(store, mode):
    store.arm_fault("pay", mode, seconds=7)
    outcome = store.pay(**PAYMENT, idempotency_key="k-1")
    assert outcome.fault.mode == mode and outcome.fault.seconds == 7
    assert len(store.list_payments(idempotency_key="k-1")) == 1
    assert store.export()["fault_log"][0]["receipt_id"] == outcome.reply["receipt"]["receipt_id"]
    # The retry with the same key finds the payment; the fault fired once.
    retry = store.pay(**PAYMENT, idempotency_key="k-1")
    assert retry.fault is None and retry.reply["replayed"] is True


def test_a_refused_request_does_not_use_up_an_armed_fault(store):
    store.arm_fault("pay", "error_after_commit")
    with pytest.raises(SandboxError):
        store.pay(**{**PAYMENT, "invoice_id": "INV-0000"})
    assert store.pay(**PAYMENT).fault is not None


def test_faults_apply_only_to_writes_and_known_modes(store):
    with pytest.raises(SandboxError):
        store.arm_fault("get_payment", "error_after_commit")
    with pytest.raises(SandboxError):
        store.arm_fault("pay", "explode")


# --- operator commands --------------------------------------------------------------------

def test_the_operator_commands(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.sqlite3"
    monkeypatch.delenv("AP_SANDBOX_KEY", raising=False)
    assert cli(["init", "--db", str(db)]) == 2 and not db.exists()
    monkeypatch.setenv("AP_SANDBOX_KEY", KEY)
    assert cli(["init", "--db", str(db)]) == 0
    assert cli(["init", "--db", str(db)]) == 2
    assert cli(["fault", "--db", str(db), "--operation", "pay", "--mode", "hang_after_commit", "--seconds", "1"]) == 0
    Store(db).pay(**PAYMENT)
    assert cli(["verify", "--db", str(db)]) == 0
    capsys.readouterr()
    assert cli(["export", "--db", str(db)]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["chain_problems"] == [] and exported["payments"][0]["invoice_id"] == "INV-1001"
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE receipts SET operation = 'refund'")
    assert cli(["verify", "--db", str(db)]) == 1


# --- over MCP -----------------------------------------------------------------------------

def _server(db: Path, key: str | None):
    pytest.importorskip("mcp.server")
    from mcp import StdioServerParameters
    env = {k: v for k, v in os.environ.items() if k != "AP_SANDBOX_KEY"}
    if key is not None:
        env["AP_SANDBOX_KEY"] = key
    return StdioServerParameters(command=sys.executable, args=["-m", "ap_sandbox.server", "--db", str(db)],
                                 cwd=str(EXAMPLES), env=env)


async def _with_session(db, key, body):
    pytest.importorskip("mcp.server")
    from mcp import ClientSession, stdio_client
    async with stdio_client(_server(db, key)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await body(session)


def test_the_server_refuses_to_start_without_the_key(db):
    pytest.importorskip("mcp.server")
    env = {k: v for k, v in os.environ.items() if k != "AP_SANDBOX_KEY"}
    for key in (None, "wrong-key-0123456789"):
        if key:
            env["AP_SANDBOX_KEY"] = key
        run = subprocess.run([sys.executable, "-m", "ap_sandbox.server", "--db", str(db)], cwd=EXAMPLES, env=env,
                             capture_output=True, text=True, timeout=60)
        assert run.returncode == 2 and "does not match" in run.stderr and KEY not in run.stderr


def test_a_payment_and_its_receipt_over_mcp(db):
    from vais.mcp import extract_mcp_result_data

    async def body(session):
        tools = {tool.name for tool in (await session.list_tools()).tools}
        assert {"pay", "get_vendor", "list_payments", "get_receipt"} <= tools
        paid = extract_mcp_result_data(await session.call_tool("pay", {**PAYMENT, "amount": 1250.0, "idempotency_key": "k"}))
        found = extract_mcp_result_data(await session.call_tool("list_payments", {"idempotency_key": "k"}))
        receipt = extract_mcp_result_data(await session.call_tool("get_receipt", {"receipt_id": paid["receipt"]["receipt_id"]}))
        refused = await session.call_tool("pay", {**PAYMENT, "invoice_id": "INV-0000"})
        return paid, found, receipt, refused

    paid, found, receipt, refused = asyncio.run(_with_session(db, KEY, body))
    assert paid["amount"] == "1250.00" and found["payments"][0]["payment_id"] == paid["payment_id"]
    assert receipt["digest"] == paid["receipt"]["digest"]
    assert refused.is_error and len(Store(db).list_payments()) == 1


def _protected_pay(db, timeout):
    """One payment through VAIS's MCPProtectedClient, as the gateway would send it."""
    from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
    from vais.mcp import MCPEffectMapping, MCPProfile, MCPProtectedClient, MCPToolBinding
    from vais.models import PlannedAction, TaskContract, TrustedValue

    profile = MCPProfile((MCPToolBinding("ap", "pay", "mcp:ap:pay", effect=MCPEffectMapping(
        "payment", {name: name for name in PAYMENT}, acknowledge={"invoice_id": "invoice_id"})),))
    policy = Policy(version=3, default_action="deny", tools={"mcp:ap:pay": ToolPolicy(True, {n: ArgumentPolicy() for n in PAYMENT})})
    action = PlannedAction("mcp:ap:pay", {name: TrustedValue(value, source="user") for name, value in PAYMENT.items()})

    async def body(session):
        client = MCPProtectedClient(server_id="ap", session=session, profile=profile, monitor=ReferenceMonitor(policy),
                                    call_timeout=timeout)
        return await client.execute(action, TaskContract(allowed_tools={"mcp:ap:pay"}))

    return asyncio.run(_with_session(db, KEY, body))


@pytest.mark.parametrize("mode", ["hang_after_commit", "crash_after_commit"])
def test_a_reply_lost_after_commit_is_indeterminate_to_vais_while_the_backend_paid(db, mode):
    Store(db).arm_fault("pay", mode, seconds=30)
    record = _protected_pay(db, timeout=3)
    assert record.call_state.value == "indeterminate" and record.effect is None
    payments = Store(db).list_payments()
    assert len(payments) == 1 and payments[0]["invoice_id"] == "INV-1001"


def test_an_error_reply_after_commit_is_recorded_by_vais_as_an_observed_call(db):
    # Inventory gap R5: an MCP error result is not an exception, so VAIS records the call as
    # observed with a requested effect, although the reply says it failed. The sandbox makes
    # this visible; closing it is step 2 of the integration sequence.
    Store(db).arm_fault("pay", "error_after_commit")
    record = _protected_pay(db, timeout=10)
    assert record.call_state.value == "observed" and record.effect.confidence.value == "requested"
    assert len(Store(db).list_payments()) == 1
