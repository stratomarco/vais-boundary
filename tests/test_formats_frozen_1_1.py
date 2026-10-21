"""Formats added since 1.0 are frozen the same way (docs/formats.md, DEC-074).

The samples in ``tests/data/formats-1.1`` must load, and be acted on, in every later 1.x release.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil

from vais import ApprovalStore, ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy, load_mcp_profile
from vais.gateway import INDETERMINATE_DIR, ContractRegistry, Gateway, GatewayOutcomeKind, IndeterminateCall
from vais.mcp import idempotency_key
from vais.models import PlannedAction, TaskContract, TrustedValue, action_fingerprint

SAMPLES = Path(__file__).resolve().parent / "data" / "formats-1.1"
TOKEN = "formats-1.1-sample-token"
PAY = {"vendor_id": "V-100", "bank_account_id": "ACCT-NW-001", "invoice_id": "INV-1001", "amount": "1250.00"}


def test_profile_version_2_loads_with_every_feature():
    profile = load_mcp_profile(SAMPLES / "mcp-profile-v2.yaml")
    pay = profile.by_canonical_tool("mcp:ap:pay")
    assert profile.version == 2 and pay.consequential and pay.receipt == "receipt"
    assert pay.idempotency_argument == "idempotency_key" and pay.effect.confirm is not None and pay.mints
    assert not profile.by_canonical_tool("mcp:ap:find_payment").consequential


def test_the_indeterminate_call_record_loads():
    entry = IndeterminateCall.load(SAMPLES / "state" / "indeterminate-call.json")
    assert entry.status == "unresolved" and entry.tool == "mcp:ap:pay" and entry.arguments == PAY
    assert entry.identity == ("clerk-1", "run-1", "acme", "pay-batch") and entry.idempotency_key.startswith("vais-")


class Backend:
    def __init__(self) -> None:
        self.sent = []

    async def call_tool(self, name, arguments=None):
        self.sent.append((name, dict(arguments or {})))
        if name == "find_payment":
            return {"found": False}  # the read-back cannot tell, so only the resolution settles it
        return {"payment_id": "PAY-2", "invoice_id": arguments["invoice_id"], "amount": arguments["amount"]}


def test_a_gateway_acts_on_the_record_and_its_resolution(tmp_path):
    # The record holds the session's other payments until reconciled; the resolution says it
    # did not happen, which releases them and keeps the record for its exact retry.
    directory = tmp_path / "pending" / INDETERMINATE_DIR
    directory.mkdir(parents=True)
    entry = IndeterminateCall.load(SAMPLES / "state" / "indeterminate-call.json")
    shutil.copy(SAMPLES / "state" / "indeterminate-call.json", directory / f"{entry.call_id}.json")
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    from vais.gateway import token_digest
    (contracts / "run-1.yaml").write_text(
        "version: 1\n"
        f"token_sha256: {token_digest(TOKEN)}\n"
        "principal_id: clerk-1\nsession_id: run-1\ntenant_id: acme\ncapability_id: pay-batch\n"
        "allowed_tools: [mcp:ap:pay]\n"
        "bound_arguments:\n  mcp:ap:pay: {vendor_id: V-100, bank_account_id: ACCT-NW-001}\n", encoding="utf-8")
    policy = Policy(version=5, default_action="deny", tools={"mcp:ap:pay": ToolPolicy(True, {
        "vendor_id": ArgumentPolicy("trusted"), "bank_account_id": ArgumentPolicy("trusted"),
        "invoice_id": ArgumentPolicy(), "amount": ArgumentPolicy()}, max_calls=1)})
    backend = Backend()
    gateway = Gateway(profile=load_mcp_profile(SAMPLES / "mcp-profile-v2.yaml"), monitor=ReferenceMonitor(policy),
                      registry=ContractRegistry(contracts), sessions={"ap": backend},
                      approval_store=ApprovalStore(tmp_path / "approvals.json"), pending_dir=tmp_path / "pending")
    other = {**PAY, "invoice_id": "INV-1002"}
    assert asyncio.run(gateway.call(TOKEN, "ap.pay", other)).kind is GatewayOutcomeKind.DENIED  # held
    shutil.copy(SAMPLES / "state" / "indeterminate-resolution.json", directory / f"{entry.call_id}.resolution.json")
    assert asyncio.run(gateway.call(TOKEN, "ap.pay", other)).kind is GatewayOutcomeKind.ALLOWED
    resolved = [e for e in gateway.audit.events if e.event_type == "indeterminate_resolved"]
    assert [(e.details["outcome"], e.details["by"]) for e in resolved] == [("did_not_happen", "ops-lead")]
    assert IndeterminateCall.load(directory / f"{entry.call_id}.json").status == "did_not_happen"


def test_the_idempotency_key_derivation_is_frozen():
    # The sample's key was derived by 1.1's gateway; a retry after an upgrade must send the same one.
    entry = IndeterminateCall.load(SAMPLES / "state" / "indeterminate-call.json")
    contract = TaskContract(allowed_tools={"mcp:ap:pay"}, principal_id="clerk-1", session_id="run-1",
                            tenant_id="acme", capability_id="pay-batch")
    action = PlannedAction("mcp:ap:pay", {k: TrustedValue(v, source="sample") for k, v in entry.arguments.items()})
    assert action_fingerprint(action) == entry.action_fingerprint
    assert idempotency_key(action, contract) == entry.idempotency_key
