"""Write the format samples VAIS produces that are new since 1.0 (DEC-074).

Run once, on 2026-10-21. Like formats-1.0/generate.py it refuses to overwrite anything: a
frozen sample is never regenerated.

    PYTHONPATH=src python tests/data/formats-1.1/generate.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import sys
import tempfile

from vais import ApprovalStore, ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy, load_mcp_profile
from vais.gateway import INDETERMINATE_DIR, ContractRegistry, Gateway, resolve_indeterminate_call, token_digest

HERE = Path(__file__).resolve().parent
TOKEN = "formats-1.1-sample-token"
CONTRACT = f"""\
version: 1
token_sha256: {token_digest(TOKEN)}
principal_id: clerk-1
session_id: run-1
tenant_id: acme
capability_id: pay-batch
allowed_tools: [mcp:ap:pay]
bound_arguments:
  mcp:ap:pay: {{vendor_id: V-100, bank_account_id: ACCT-NW-001}}
"""


class LostReply:
    async def call_tool(self, name, arguments=None):
        raise ConnectionResetError


def main() -> int:
    targets = [HERE / "state" / "indeterminate-call.json", HERE / "state" / "indeterminate-resolution.json"]
    if any(path.exists() for path in targets):
        print("refusing to overwrite frozen samples", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        (work / "contracts").mkdir()
        (work / "contracts" / "run-1.yaml").write_text(CONTRACT, encoding="utf-8")
        policy = Policy(version=5, default_action="deny", tools={"mcp:ap:pay": ToolPolicy(True, {
            "vendor_id": ArgumentPolicy("trusted"), "bank_account_id": ArgumentPolicy("trusted"),
            "invoice_id": ArgumentPolicy(), "amount": ArgumentPolicy()}, max_calls=1)})
        gateway = Gateway(profile=load_mcp_profile(HERE / "mcp-profile-v2.yaml"), monitor=ReferenceMonitor(policy),
                          registry=ContractRegistry(work / "contracts"), sessions={"ap": LostReply()},
                          approval_store=ApprovalStore(work / "approvals.json"), pending_dir=work / "pending")
        asyncio.run(gateway.call(TOKEN, "ap.pay", {"vendor_id": "V-100", "bank_account_id": "ACCT-NW-001",
                                                    "invoice_id": "INV-1001", "amount": "1250.00"}))
        (record,) = (work / "pending" / INDETERMINATE_DIR).glob("*.json")
        resolution = resolve_indeterminate_call(work / "pending", record.stem, "did_not_happen", by="ops-lead")
        shutil.copy(record, targets[0])
        shutil.copy(resolution, targets[1])
    print("wrote", *targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
