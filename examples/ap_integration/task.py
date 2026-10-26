"""The trusted task: what an authenticated clerk asked for, read strictly.

Both the contract builder and the verifier read tasks through this module. It imports nothing
from VAIS, so the verifier stays independent of it.

A task combines any of:
- ``invoices``: invoice id -> approved amount, paid to ``vendor``; with ``remittance``, each
  payment's remittance is sent to the vendor's contact on file;
- ``payroll_period``: the payroll summary the clerk wants checked first;
- ``messages`` and ``portal``: vendor mail and the vendor's portal to read;
- ``post_to``: the internal channel a note goes to.

Payments above the policy's threshold need an operator's approval of the exact payment; the
task does not grant it.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import yaml

REQUIRED = {"version", "batch_id", "requester", "tenant", "vendor"}
OPTIONAL = {"invoices", "remittance", "payroll_period", "messages", "portal", "post_to", "kind"}


def parse_task(raw: Any, where: str = "task") -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError(f"{where}: not a version 1 task")
    missing, unknown = REQUIRED - set(raw), set(raw) - REQUIRED - OPTIONAL
    if missing or unknown:
        raise ValueError(f"{where}: missing {sorted(missing)}, unknown {sorted(unknown)}")
    for key in ("batch_id", "requester", "tenant", "vendor"):
        if not isinstance(raw[key], str) or not raw[key].strip():
            raise ValueError(f"{where}.{key}: must be a non-empty string")
    task = dict(raw)
    invoices = task.setdefault("invoices", {})
    if not isinstance(invoices, dict):
        raise ValueError(f"{where}.invoices: must map invoice ids to amounts")
    for invoice, amount in invoices.items():
        try:
            if Decimal(str(amount)) <= 0:
                raise InvalidOperation
        except InvalidOperation:
            raise ValueError(f"{where}.invoices.{invoice}: not a positive amount") from None
    task.setdefault("remittance", False)
    task.setdefault("messages", [])
    task.setdefault("portal", False)
    if task["remittance"] and not invoices:
        raise ValueError(f"{where}: a remittance needs invoices to pay")
    if not (invoices or task.get("post_to")):
        raise ValueError(f"{where}: the task asks for nothing to be done")
    return task


def load_task(path: str | Path) -> dict[str, Any]:
    return parse_task(yaml.safe_load(Path(path).read_text(encoding="utf-8")), str(path))
