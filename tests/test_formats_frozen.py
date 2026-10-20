"""1.0's file formats are frozen (plan of record §1b, step 3; docs/formats.md).

Every sample in ``tests/data/formats-1.0`` must load in every 1.x release, and the monitor must
decide the sample actions exactly as ``expected-decisions.json`` records. A failure here means a
change is incompatible with 1.0, not that the sample needs regenerating.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pytest

from vais import (
    ApprovalStore, ContractRegistry, ReferenceMonitor, RevocationList, SessionLedger, grant_pending_request,
    load_gateway_contract, load_invariants, load_mcp_profile, load_policy,
)
from vais.audit import verify_jsonl
from vais.gateway import _SessionContext
from vais.gateway_server import load_gateway_config

SAMPLES = Path(__file__).resolve().parent / "data" / "formats-1.0"
spec = importlib.util.spec_from_file_location("formats_1_0_generate", SAMPLES / "generate.py")
generate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generate
spec.loader.exec_module(generate)


@pytest.mark.parametrize("version", range(1, 7))
def test_every_policy_version_loads(version):
    assert load_policy(SAMPLES / f"policy-v{version}.yaml").version == version


def test_the_other_operator_files_load():
    load_invariants(SAMPLES / "invariants-v1.yaml")
    load_mcp_profile(SAMPLES / "mcp-profile-v1.yaml")
    full = load_mcp_profile(SAMPLES / "mcp-profile-v1-full.yaml")
    assert {b.canonical_tool for b in full.bindings if b.writes} == {"mcp:ap:create_invoice"}
    load_gateway_config(SAMPLES / "gateway" / "gateway.yaml")
    _, contract = load_gateway_contract(SAMPLES / "contract-v1.yaml")
    assert contract.value_budgets and contract.allowed_values and contract.budgets


def test_decisions_match_the_frozen_snapshot():
    expected = json.loads((SAMPLES / "expected-decisions.json").read_text(encoding="utf-8"))
    assert generate.snapshot() == expected


def _copy(tmp_path: Path, name: str) -> Path:
    target = tmp_path / name
    shutil.copy(SAMPLES / "state" / name, target)
    return target


def test_the_approval_store_file_loads_with_its_grants(tmp_path):
    store = ApprovalStore(_copy(tmp_path, "approvals.json"), clock=lambda: generate.CLOCK)
    contract, cases = generate.policy_contract(), generate.policy_cases()
    assert not store.consume(cases["pay_over_threshold"], contract)  # consumed when frozen
    assert store.consume(cases["email_untrusted_origin"], contract)  # still granted


def test_the_revocation_file_still_revokes(tmp_path):
    monitor = ReferenceMonitor(load_policy(SAMPLES / "policy-v1.yaml"), revocations=RevocationList(_copy(tmp_path, "revocations.json")))
    decision = monitor.evaluate(generate.policy_cases()["email_bound_recipient"], generate.policy_contract())
    assert decision.type.value == "deny"


def test_the_ledger_file_keeps_its_history(tmp_path):
    _, contract = load_gateway_contract(SAMPLES / "contract-v1.yaml")
    ledger = SessionLedger(contract, _copy(tmp_path, "ledger.json"))
    assert ledger.calls(generate.PAY) == 2
    assert str(ledger.total(generate.PAY, "amount")) in {"1900", "1900.00"}


def test_the_gateway_session_context_file_loads(tmp_path):
    context = _SessionContext(_copy(tmp_path, "session-context.json"))
    assert context.level.value == "internal"
    assert [m.value for m in context.minted[(generate.PAY, "invoice_id")]] == ["INV-2001"]


def test_a_pending_request_file_can_still_be_granted(tmp_path):
    (tmp_path / "contracts").mkdir()
    shutil.copy(SAMPLES / "contract-v1.yaml", tmp_path / "contracts" / "contract-v1.yaml")
    request = json.loads((SAMPLES / "state" / "pending-request.json").read_text(encoding="utf-8"))
    fingerprint = grant_pending_request(_copy(tmp_path, "pending-request.json"), ContractRegistry(tmp_path / "contracts"),
                                        ApprovalStore(tmp_path / "approvals.json"))
    assert fingerprint == request["action_fingerprint"]


def test_the_audit_log_still_verifies():
    report = verify_jsonl((SAMPLES / "state" / "audit.jsonl").read_text(encoding="utf-8"))
    assert report.ok and report.events == 3
