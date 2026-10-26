"""The gateway contract for a task: authority fixed before the agent reads anything (R1).

Everything in the contract comes from the trusted task (task.py): who asked, for which tenant,
which vendor, which invoices and how much each, which messages, which payroll period, which
channel. The bank account and the remittance contact are not in it: the gateway takes them
from the vendor master's reply, through the profile's declared mints, so they come from the
system of record and never from what the agent read.
"""
from __future__ import annotations

from typing import Any

import yaml


def contract_for(task: dict[str, Any], token_sha256: str) -> dict[str, Any]:
    tools: list[str] = []
    scopes: list[str] = []
    bound: dict[str, dict[str, Any]] = {}
    allowed: dict[str, dict[str, Any]] = {}
    budgets: dict[str, Any] = {}

    def allow(tool: str, scope: str) -> None:
        tools.append(f"mcp:ap:{tool}")
        if scope not in scopes:
            scopes.append(scope)

    if task.get("payroll_period"):
        allow("get_payroll_summary", "payroll:read")
        bound["mcp:ap:get_payroll_summary"] = {"period": task["payroll_period"]}
    if task["messages"]:
        allow("read_message", "inbox:read")
        allowed["mcp:ap:read_message"] = {"message_id": {"values": list(task["messages"])}}
    if task["portal"]:
        allow("read_portal", "vendors:read")
        bound["mcp:ap:read_portal"] = {"vendor_id": task["vendor"]}
    invoices = list(task["invoices"])
    if invoices:
        allow("get_invoice", "invoices:read")
        allow("get_vendor", "vendors:read")
        allow("pay", "payments:send")
        bound["mcp:ap:get_vendor"] = {"vendor_id": task["vendor"]}
        bound["mcp:ap:pay"] = {"vendor_id": task["vendor"]}
        allowed["mcp:ap:get_invoice"] = {"invoice_id": {"values": invoices}}
        # Each invoice is paid at most once in the session, for at most its approved amount.
        allowed["mcp:ap:pay"] = {"invoice_id": {"values": invoices, "once": True}}
        budgets["mcp:ap:pay"] = {"amount": {"per": "invoice_id", "limits": {
            invoice: float(amount) for invoice, amount in task["invoices"].items()}}}
    if task["remittance"]:
        allow("build_remittance", "payments:remit")
        allow("send_remittance", "email:external")
    if task.get("post_to"):
        allow("post_chat", "chat:internal")
        bound["mcp:ap:post_chat"] = {"channel": task["post_to"]}

    contract: dict[str, Any] = {
        "version": 1,
        "token_sha256": token_sha256,
        "principal_id": task["requester"],
        "session_id": task["batch_id"],
        "tenant_id": task["tenant"],
        "capability_id": "ap-task",
        "allowed_tools": tools,
        "granted_scopes": scopes,
        "bound_arguments": bound,
    }
    if allowed:
        contract["allowed_values"] = allowed
    if budgets:
        contract["value_budgets"] = budgets
    return contract


def render(contract: dict[str, Any]) -> str:
    header = ("# Written by `python -m ap_integration setup` from the task. Operator-owned: the agent\n"
              "# never reads or writes it. Deleting it ends the session at its next call.\n")
    return header + yaml.safe_dump(contract, sort_keys=False)
