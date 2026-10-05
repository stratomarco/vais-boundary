"""The evidence index covers every study and every finding that cites one (E4).

The index itself is regenerated with ``python tools/evidence_index.py``, which needs full git
history for the registration commits; these checks need none, so they also run on CI's shallow
checkout.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("evidence_index", ROOT / "tools" / "evidence_index.py")
index = importlib.util.module_from_spec(spec)
sys.modules["evidence_index"] = index  # its dataclasses look their module up
spec.loader.exec_module(index)


def covered_paths() -> set[str]:
    return {p for s in index.STUDIES for p in (*s.paths, *s.registrations, *s.results)}


def test_every_experiment_folder_is_a_study():
    folders = {p.name for p in (ROOT / "experiments").iterdir() if p.is_dir() and not p.name.startswith("__")}
    covered = {p.split("/")[1] for p in covered_paths() if p.startswith("experiments/")}
    assert folders <= covered, f"not in the evidence index: {sorted(folders - covered)}"


def test_every_finding_that_cites_an_experiment_is_in_a_study():
    findings = index.ledger("findings")
    in_studies = {f["id"] for s in index.STUDIES for f in index.study_findings(s, findings)}
    citing = {f["id"] for f in findings if any(str(e).startswith("experiments/") for e in f.get("evidence") or [])}
    assert citing <= in_studies, f"findings missing from the index: {sorted(citing - in_studies)}"


def test_named_files_exist_and_the_index_is_committed():
    for path in covered_paths():
        assert (ROOT / path).exists(), path
    text = (ROOT / "docs" / "evidence-index.md").read_text(encoding="utf-8")
    assert all(f"| {s.name} |" in text for s in index.STUDIES)
