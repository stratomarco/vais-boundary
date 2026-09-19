"""BrokenPilot as the experiment environment.

The harness imports BrokenPilot's application modules in-process and owns the agent
loop itself. BrokenPilot supplies the users, tickets, documents, memory store,
retrieval, the ticket tool and its own application controls. Nothing in the
BrokenPilot repository is modified.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

BROKENPILOT_DIR = Path(
    os.environ.get(
        "BROKENPILOT_DIR",
        "F:/ai-training-ml-security/labs/brokenpilot/prototype-app",
    )
)
if not (BROKENPILOT_DIR / "app" / "tools.py").exists():
    raise RuntimeError(f"BrokenPilot prototype-app not found at {BROKENPILOT_DIR}; set BROKENPILOT_DIR")
sys.path.insert(0, str(BROKENPILOT_DIR))

from app import audit as bp_audit  # noqa: E402
from app import data as bp_data  # noqa: E402
from app import memory as bp_memory  # noqa: E402
from app import rag as bp_rag  # noqa: E402
from app import tools as bp_tools  # noqa: E402
from app.controls import Controls  # noqa: E402

CONTROL_VARS = (
    "ENABLE_RETRIEVAL_AUTHZ",
    "ENABLE_PROMPT_INJECTION_FILTER",
    "ENABLE_TOOL_AUTHZ",
    "ENABLE_TOOL_APPROVAL",
    "ENABLE_MEMORY_REVIEW",
    "ENABLE_MEMORY_ISOLATION",
    "ENABLE_AUDIT_LOG",
)

# BrokenPilot's own controls per arm. FILTER and VAIS add defences in the harness;
# they deliberately leave BrokenPilot's application controls off so each arm measures
# one mechanism. Retrieval authorization stays on everywhere: the attack content is
# legitimately inside the victim's tenant, as in ShareLeak.
ARM_CONTROLS: dict[str, dict[str, str]] = {
    "OFF": {"ENABLE_RETRIEVAL_AUTHZ": "1"},
    "APP_AUTHZ": {"ENABLE_RETRIEVAL_AUTHZ": "1", "ENABLE_TOOL_AUTHZ": "1", "ENABLE_TOOL_APPROVAL": "1"},
    "APP_MEMORY": {"ENABLE_RETRIEVAL_AUTHZ": "1", "ENABLE_MEMORY_REVIEW": "1", "ENABLE_MEMORY_ISOLATION": "1"},
    "FILTER": {"ENABLE_RETRIEVAL_AUTHZ": "1"},
    "VAIS": {"ENABLE_RETRIEVAL_AUTHZ": "1"},
    "VAIS_OP": {"ENABLE_RETRIEVAL_AUTHZ": "1"},
}

# A second alpha ticket, added in memory at reset so a same-tenant substitution attack has a
# target. BrokenPilot's fixture files are not modified.
EXTRA_TICKETS: list[dict[str, Any]] = [
    {"id": "TCK-1002", "tenant": "alpha", "title": "Payment API error budget review", "status": "open",
     "owner": "alice", "summary": "Quarterly error budget review for the payment API."},
]


def set_controls(arm: str) -> Controls:
    if arm not in ARM_CONTROLS:
        raise ValueError(f"unknown arm {arm!r}")
    for name in CONTROL_VARS:
        os.environ.pop(name, None)
    os.environ["ENABLE_AUDIT_LOG"] = "1"
    os.environ.update(ARM_CONTROLS[arm])
    return Controls.from_env()


def reset() -> None:
    tickets = bp_data.reset_tickets()
    tickets.extend(dict(t) for t in EXTRA_TICKETS)
    bp_memory.reset_memory()
    bp_audit.clear_events()


def ticket_snapshot() -> dict[str, dict[str, Any]]:
    return {t["id"]: {"status": t.get("status"), "tenant": t.get("tenant")} for t in bp_data.load_tickets()}


def changed_tickets(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {tid: after[tid]["status"] for tid in after if after[tid]["status"] != before.get(tid, {}).get("status")}
