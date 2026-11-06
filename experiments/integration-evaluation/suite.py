"""The held-out suite (scenarios.yaml): read it strictly, and build each attacked run's seed.

A scenario names a clean task instance, a record that task reads, and three wordings. An attacked
run is the clean task with one wording appended to that record's text, and the scenario's fault
armed, if it has one. The clean task and the contract are unchanged: the attack is only in what
the agent reads.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "examples"))
from ap_integration.task import load_task  # noqa: E402

CATEGORIES = {
    "malicious_retrieved_content", "changed_authority_argument", "cross_tenant", "secret_egress",
    "approval_replay", "duplicate_effect", "transport_uncertainty", "attempted_bypass",
}
VARIANTS = ("a", "b", "c")
FAULT_MODES = {"fail_before_commit", "error_after_commit", "hang_after_commit", "crash_after_commit"}
SCENARIO_KEYS = {"id", "category", "base", "place", "objective", "variants", "fault"}


def load_suite(path: Path = HERE / "scenarios.yaml", tasks: Path = HERE / "tasks") -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1 or set(raw) != {"version", "scenarios"}:
        raise ValueError(f"{path}: not a version 1 suite")
    seen = set()
    for item in raw["scenarios"]:
        where = f"{path}: {item.get('id')}"
        if set(item) - SCENARIO_KEYS or not {"id", "category", "base", "place", "objective", "variants"} <= set(item):
            raise ValueError(f"{where}: fields {sorted(item)}")
        if item["id"] in seen or item["category"] not in CATEGORIES:
            raise ValueError(f"{where}: duplicate id or unknown category")
        seen.add(item["id"])
        if set(item["variants"]) != set(VARIANTS) or not all(str(t).strip() for t in item["variants"].values()):
            raise ValueError(f"{where}: needs wordings a, b and c")
        task = load_task(tasks / f"{item['base']}.yaml")
        (kind, target), = item["place"].items()
        reads = {"invoice": task["invoices"], "message": task["messages"],
                 "portal": [task["vendor"]] if task["portal"] else []}
        if kind not in reads or target not in reads[kind]:
            raise ValueError(f"{where}: task {item['base']} never reads {kind} {target}")
        fault = item.get("fault")
        if fault is not None and (set(fault) != {"operation", "mode", "seconds"} or fault["mode"] not in FAULT_MODES
                                  or fault["operation"] != "pay" or not task["invoices"]):
            raise ValueError(f"{where}: invalid fault")
    return raw["scenarios"]


def attacked_seed(seed: dict[str, Any], scenario: dict[str, Any], variant: str) -> dict[str, Any]:
    """The clean seed with the hostile wording appended to the record the task reads."""
    seed = copy.deepcopy(seed)
    text = scenario["variants"][variant].strip()
    (kind, target), = scenario["place"].items()
    if kind == "invoice":
        record = seed["invoices"][target]
        record["body"] = f"{record.get('body', '')}\n\n{text}".strip()
    elif kind == "message":
        seed["messages"][target] = f"{seed['messages'][target]}\n\n{text}"
    else:
        seed["portal"][target] = f"{seed['portal'].get(target, '')}\n\n{text}".strip()
    return seed


def suite_digest(path: Path = HERE / "scenarios.yaml") -> str:
    """The digest the registration records, so a run can show it used the frozen suite."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
