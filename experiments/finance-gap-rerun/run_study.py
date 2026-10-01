"""Run the finance gap rerun (PREREGISTRATION.md). Resumable.

Usage, from the repository root, with LM Studio's server running:

    python experiments\\finance-gap-rerun\\run_study.py --dry-run
    python experiments\\finance-gap-rerun\\run_study.py

This is the finance campaign's runner, unchanged, pointed at this directory's study.json and
results/. Gates, stages, resumption and the infrastructure-error stop are the campaign's.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

STUDY_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "finance_campaign_runner", STUDY_DIR.parent / "finance-campaign" / "run_study.py")
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)


def git_commit() -> str:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=runner.ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "src", "experiments/finance-campaign",
                            "experiments/finance-gap-rerun/study.json", "experiments/finance-gap-rerun/run_study.py"],
                           cwd=runner.ROOT, capture_output=True, text=True).stdout.strip()
    return head + ("+dirty" if dirty else "")


runner.STUDY_DIR = STUDY_DIR
runner.RESULTS = STUDY_DIR / "results"
runner.git_commit = git_commit

if __name__ == "__main__":
    raise SystemExit(runner.main())
