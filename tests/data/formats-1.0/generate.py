"""Write the 1.0 format samples that VAIS itself produces, and the decisions snapshot.

Run once, on 2026-10-20, to freeze 1.0's formats (plan of record §1b, step 3). It refuses to
overwrite anything: a frozen sample is never regenerated. If a 1.x change makes a sample fail
to load, or a decision in ``expected-decisions.json`` change, the change is incompatible.

    PYTHONPATH=src python tests/data/formats-1.0/generate.py
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from vais import (
    ApprovalStore, AuditTrail, ConfidentialityLevel, PlannedAction, Provenance, ReferenceMonitor,
    RevocationList, SessionLedger, TaskContract, TrustedValue, TrustLevel, Value, action_fingerprint,
    load_gateway_contract, load_policy,
)
from vais.gateway import MintedValue, _SessionContext

HERE = Path(__file__).resolve().parent
CLOCK = 1_800_000_000.0  # inside contract-v1's validity window

EMAIL, PAY = "mcp:ops:send_email", "mcp:ap:pay"
TEAM = "ap-team@acme.example"
TRUSTED_ORIGIN = Provenance("user", TrustLevel.TRUSTED)
UNTRUSTED_ORIGIN = Provenance("mcp:ops:get_incident", TrustLevel.UNTRUSTED)


def untrusted(data, confidentiality=ConfidentialityLevel.PUBLIC) -> Value:
    return Value(data, Provenance("mcp:ops:get_incident", TrustLevel.UNTRUSTED, confidentiality=confidentiality))


def policy_contract() -> TaskContract:
    return TaskContract(
        allowed_tools={EMAIL, PAY},
        bound_arguments={(EMAIL, "recipient"): TrustedValue(TEAM)},
        granted_scopes={"email:send", "payments:write"},
        principal_id="clerk-1", session_id="sample", tenant_id="acme", capability_id="payables",
    )


def policy_cases() -> dict[str, PlannedAction]:
    body = TrustedValue("weekly summary")
    return {
        "email_bound_recipient": PlannedAction(EMAIL, {"recipient": TrustedValue(TEAM), "body": body}, TRUSTED_ORIGIN),
        "email_untrusted_recipient": PlannedAction(EMAIL, {"recipient": untrusted("attacker@evil.test"), "body": body}, TRUSTED_ORIGIN),
        "email_confidential_body": PlannedAction(
            EMAIL, {"recipient": TrustedValue(TEAM), "body": TrustedValue("salaries", confidentiality=ConfidentialityLevel.CONFIDENTIAL)},
            TRUSTED_ORIGIN),
        "email_undeclared_argument": PlannedAction(EMAIL, {"recipient": TrustedValue(TEAM), "body": body, "cc": TrustedValue(TEAM)}, TRUSTED_ORIGIN),
        "email_untrusted_origin": PlannedAction(EMAIL, {"recipient": TrustedValue(TEAM), "body": body}, UNTRUSTED_ORIGIN),
        "pay_under_threshold": PlannedAction(PAY, {"amount": TrustedValue(500), "invoice_id": TrustedValue("INV-1001")}, TRUSTED_ORIGIN),
        "pay_over_threshold": PlannedAction(PAY, {"amount": TrustedValue(5000), "invoice_id": TrustedValue("INV-1001")}, TRUSTED_ORIGIN),
        "unknown_tool": PlannedAction("mcp:ops:delete_all", {}, TRUSTED_ORIGIN),
    }


def contract_sequence() -> list[tuple[str, PlannedAction]]:
    """Evaluated in order against one session ledger, so budgets and single use apply."""
    def pay(invoice: str, amount: int) -> PlannedAction:
        return PlannedAction(PAY, {"amount": TrustedValue(amount), "invoice_id": TrustedValue(invoice)}, TRUSTED_ORIGIN)
    return [
        ("pay_inv1001_1000", pay("INV-1001", 1000)),
        ("pay_inv1001_again_200", pay("INV-1001", 200)),
        ("pay_inv1002_over_cap_3500", pay("INV-1002", 3500)),
        ("pay_inv1002_900", pay("INV-1002", 900)),
        ("pay_unlisted_invoice", pay("INV-9999", 10)),
        ("email_bound_recipient", PlannedAction(EMAIL, {"recipient": TrustedValue(TEAM), "body": TrustedValue("done")}, TRUSTED_ORIGIN)),
        ("email_other_recipient", PlannedAction(EMAIL, {"recipient": TrustedValue("cfo@acme.example"), "body": TrustedValue("done")}, TRUSTED_ORIGIN)),
    ]


def operator_approvals(contract: TaskContract, path: Path | None = None) -> ApprovalStore:
    """Policy v6 requires an exact approval for every payment: grant each one, as an operator
    would, so the contract's single use, caps and budget are what decide."""
    store = ApprovalStore(path, clock=lambda: CLOCK)
    for _, action in contract_sequence():
        if action.tool == PAY:
            store.grant(action, contract)
    return store


def decision(d) -> list:
    return [d.type.value, list(d.reasons)]


def snapshot() -> dict:
    out: dict = {"policies": {}, "contract-v1 with policy-v6": {}}
    for version in range(1, 7):
        monitor = ReferenceMonitor(load_policy(HERE / f"policy-v{version}.yaml"), clock=lambda: CLOCK)
        # Each case on a fresh session ledger, so a call limit does not mask the other checks.
        out["policies"][f"policy-v{version}"] = {
            name: decision(monitor.evaluate(action, policy_contract(), ledger=SessionLedger(policy_contract())))
            for name, action in policy_cases().items()}
    _, contract = load_gateway_contract(HERE / "contract-v1.yaml")
    monitor = ReferenceMonitor(load_policy(HERE / "policy-v6.yaml"), clock=lambda: CLOCK)
    ledger, approvals = SessionLedger(contract), operator_approvals(contract)
    for name, action in contract_sequence():
        out["contract-v1 with policy-v6"][name] = decision(
            monitor.evaluate(action, contract, approval_store=approvals, ledger=ledger))
    return out


def write_state() -> None:
    contract = policy_contract()
    approved = policy_cases()["pay_over_threshold"]
    store = ApprovalStore(HERE / "state" / "approvals.json", clock=lambda: CLOCK)
    store.grant(approved, contract)
    store.grant(policy_cases()["email_untrusted_origin"], contract, ttl_seconds=600)
    store.consume(approved, contract)

    revocations = RevocationList(HERE / "state" / "revocations.json")
    revocations.revoke_session(contract)
    revocations.revoke_capability(TaskContract(allowed_tools={EMAIL}, principal_id="clerk-2", session_id="s2",
                                               tenant_id="acme", capability_id="email-only"))

    _, sample_contract = load_gateway_contract(HERE / "contract-v1.yaml")
    ledger = SessionLedger(sample_contract, HERE / "state" / "ledger.json")
    monitor = ReferenceMonitor(load_policy(HERE / "policy-v6.yaml"), clock=lambda: CLOCK)
    approvals = operator_approvals(sample_contract)
    for _, action in contract_sequence():
        monitor.evaluate(action, sample_contract, approval_store=approvals, ledger=ledger)

    context = _SessionContext(HERE / "state" / "session-context.json")
    context.observe(ConfidentialityLevel.INTERNAL)
    context.mint(((PAY, "invoice_id"),), MintedValue("INV-2001", ConfidentialityLevel.INTERNAL, "mcp:ap:create_invoice"))

    request = PlannedAction(PAY, {"amount": TrustedValue(5000), "invoice_id": TrustedValue("INV-1002")})
    body = {
        "version": 1, "request_id": "frozen-sample-request", "tool": request.tool,
        "arguments": request.plain_arguments(), "action_fingerprint": action_fingerprint(request),
        "principal_id": sample_contract.principal_id, "session_id": sample_contract.session_id,
        "tenant_id": sample_contract.tenant_id, "capability_id": sample_contract.capability_id,
    }
    (HERE / "state" / "pending-request.json").write_text(json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")

    audit = AuditTrail()
    audit.record("decision", tool=PAY, decision="allow", details={"action_fingerprint": action_fingerprint(approved)})
    audit.record("decision", tool=EMAIL, decision="deny", reasons=("bound_argument_not_trusted:recipient",))
    audit.record("approval_requested", tool=PAY, details={"request_id": "frozen-sample-request"})
    audit.write_jsonl(HERE / "state" / "audit.jsonl")


def main() -> int:
    targets = [HERE / "expected-decisions.json", HERE / "state"]
    existing = [str(t) for t in targets if t.exists()]
    if existing:
        print(f"refusing to overwrite frozen samples: {existing}", file=sys.stderr)
        return 1
    (HERE / "state").mkdir()
    write_state()
    (HERE / "expected-decisions.json").write_text(json.dumps(snapshot(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for lock in (HERE / "state").glob("*.lock"):  # locking side-effects, not formats
        lock.unlink()
    print("wrote", ", ".join(sorted(p.name for p in (HERE / "state").iterdir())), "and expected-decisions.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
