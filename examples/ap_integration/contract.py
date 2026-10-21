"""The gateway contract for a task: authority fixed before the agent reads anything (R1).

Everything in the contract comes from the trusted task (task.yaml): who asked, for which
tenant, which vendor, which invoices, how much each. The bank account and the remittance
contact are not in it: the gateway takes them from the vendor master's reply, through the
profile's declared mints, so they come from the system of record and never from an invoice.
"""
from __future__ import annotations

from typing import Any

import yaml

TOOLS = ["mcp:ap:get_invoice", "mcp:ap:get_vendor", "mcp:ap:pay"]
REMITTANCE_TOOLS = ["mcp:ap:build_remittance", "mcp:ap:send_remittance"]
SCOPES = ["invoices:read", "vendors:read", "payments:send"]
REMITTANCE_SCOPES = ["payments:remit", "email:external"]


def contract_for(task: dict[str, Any], token_sha256: str) -> dict[str, Any]:
    invoices = list(task["invoices"])
    remittance = bool(task.get("remittance"))
    return {
        "version": 1,
        "token_sha256": token_sha256,
        "principal_id": task["requester"],
        "session_id": task["batch_id"],
        "tenant_id": task["tenant"],
        "capability_id": "ap-payment-run",
        "allowed_tools": TOOLS + (REMITTANCE_TOOLS if remittance else []),
        "granted_scopes": SCOPES + (REMITTANCE_SCOPES if remittance else []),
        "bound_arguments": {
            "mcp:ap:get_vendor": {"vendor_id": task["vendor"]},
            "mcp:ap:pay": {"vendor_id": task["vendor"]},
        },
        "allowed_values": {
            "mcp:ap:get_invoice": {"invoice_id": {"values": invoices}},
            # Each invoice is paid at most once in the session.
            "mcp:ap:pay": {"invoice_id": {"values": invoices, "once": True}},
        },
        # And for at most the amount the task approved for it.
        "value_budgets": {"mcp:ap:pay": {"amount": {"per": "invoice_id", "limits": {
            invoice: float(amount) for invoice, amount in task["invoices"].items()}}}},
    }


def render(contract: dict[str, Any]) -> str:
    header = ("# Written by `python -m ap_integration setup` from task.yaml. Operator-owned: the agent\n"
              "# never reads or writes it. Deleting it ends the session at its next call.\n")
    return header + yaml.safe_dump(contract, sort_keys=False)
