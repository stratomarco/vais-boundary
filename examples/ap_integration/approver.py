"""A scripted operator: approves a held payment only if it is exactly what the task approved.

It stands in for the person who runs `vais gateway-approve` after checking the request against
the approved batch. It reads the pending request the gateway wrote, and grants it once if the
payment is for an invoice in the task, to the task's vendor, to the vendor's account in the
seeded vendor master, for the approved amount. Anything else stays pending.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
from typing import Any

from vais.approvals import ApprovalStore
from vais.gateway import ContractRegistry, grant_pending_request


def approvable(request: dict[str, Any], task: dict[str, Any], seed: dict[str, Any]) -> bool:
    if request.get("tool") != "mcp:ap:pay":
        return False
    arguments = request.get("arguments") or {}
    invoice = arguments.get("invoice_id")
    vendor = seed["vendors"].get(task["vendor"], {})
    try:
        amount = Decimal(str(arguments.get("amount")))
    except InvalidOperation:
        return False
    return (invoice in task["invoices"] and arguments.get("vendor_id") == task["vendor"]
            and arguments.get("bank_account_id") == vendor.get("bank_account_id")
            and amount == Decimal(str(task["invoices"][invoice])))


def decide(request_id: str, *, pending: Path, contracts: Path, approvals: Path,
           task: dict[str, Any], seed: dict[str, Any]) -> bool:
    """Grant pending request ``request_id`` if the task approved exactly that payment."""
    if not re.fullmatch(r"[0-9a-f]{24}", request_id):
        return False
    path = pending / f"{request_id}.json"
    if not path.exists() or not approvable(json.loads(path.read_text(encoding="utf-8")), task, seed):
        return False
    grant_pending_request(path, ContractRegistry(contracts), ApprovalStore(approvals))
    return True
