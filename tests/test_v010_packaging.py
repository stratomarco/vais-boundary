from pathlib import Path

from vais import REFERENCE_BASELINE_VERSION, __version__

ROOT = Path(__file__).resolve().parents[1]


def test_v010_version_preserves_frozen_reference_baseline():
    assert __version__ == "0.12.0rc7"
    assert REFERENCE_BASELINE_VERSION == "0.9.3"
    assert (ROOT / "src" / "vais" / "adaptive_reference.py").exists()
    assert (ROOT / "docs" / "v0.10-adaptive-verification.md").exists()


def test_v0102_research_evidence_files_are_packaged_in_source_tree():
    assert (ROOT / "research" / "knowledge" / "claims.yaml").exists()
    assert (ROOT / "research" / "knowledge" / "findings.yaml").exists()
    assert (ROOT / "research" / "knowledge" / "hypotheses.yaml").exists()
    assert (ROOT / "docs" / "v0.10.2-research-integrity.md").exists()
    assert (ROOT / "src" / "vais" / "data" / "research" / "claims.yaml").read_text(encoding="utf-8") == (ROOT / "research" / "knowledge" / "claims.yaml").read_text(encoding="utf-8")
    assert (ROOT / "src" / "vais" / "data" / "research" / "sources.yaml").read_text(encoding="utf-8") == (ROOT / "research" / "knowledge" / "sources.yaml").read_text(encoding="utf-8")


def test_v0102_packaged_hypotheses_match_canonical_knowledge():
    assert (ROOT / "src" / "vais" / "data" / "research" / "hypotheses.yaml").read_text(encoding="utf-8") == (ROOT / "research" / "knowledge" / "hypotheses.yaml").read_text(encoding="utf-8")


def test_reviewer_facing_readme_and_howto_ship_in_source_package():
    assert (ROOT / "README.md").exists()
    assert (ROOT / "HOWTO.md").exists()
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    assert "include README.md" in manifest
    assert "include HOWTO.md" in manifest
