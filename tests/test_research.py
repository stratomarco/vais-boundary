import json
from pathlib import Path
import sqlite3

from vais.research import build_research_database, discover_history_roots, research_query, research_summary


ROOT = Path(__file__).resolve().parents[1]


def test_discover_history_roots_only_selects_version_directories(tmp_path: Path):
    (tmp_path / "vais-v03").mkdir()
    (tmp_path / "vais-v0.10").mkdir()
    (tmp_path / "vais-test").mkdir()
    (tmp_path / "other").mkdir()
    names = [item.name for item in discover_history_roots(tmp_path)]
    assert names == ["vais-v0.10", "vais-v03"]


def test_research_database_extracts_adaptive_metrics(tmp_path: Path):
    episode_path = tmp_path / "qwen-adaptive.jsonl"
    rows = [
        {
            "framework_version": "0.10.0",
            "target_id": "lmstudio:qwen/test",
            "workflow_id": "attack-01",
            "episode": 1,
            "reward_evaluated": True,
            "terminal_security_reward": 0.0,
            "protected_violation": False,
            "pair_delta": {"added_security_events": ["tool_added:test"]},
            "control_result": {"target_failure": False, "workflow_utility_success": True},
            "protected_result": {"target_failure": False, "attack_objective_success": False, "workflow_utility_success": False},
            "candidate": {"content_hash": "abc"},
        },
        {
            "framework_version": "0.10.0",
            "target_id": "lmstudio:qwen/test",
            "workflow_id": "attack-01",
            "episode": 2,
            "reward_evaluated": True,
            "terminal_security_reward": 0.0,
            "protected_violation": False,
            "pair_delta": {"added_security_events": []},
            "control_result": {"target_failure": False, "workflow_utility_success": True},
            "protected_result": {"target_failure": False, "attack_objective_success": False, "workflow_utility_success": True},
            "candidate": {"content_hash": "def"},
        },
    ]
    episode_path.write_text("\n".join(json.dumps(item) for item in rows) + "\n", encoding="utf-8")
    research_dir = tmp_path / "research"
    (research_dir / "knowledge").mkdir(parents=True)
    for name, key in (("claims.yaml", "claims"), ("findings.yaml", "findings"), ("decisions.yaml", "decisions"), ("limitations.yaml", "limitations"), ("terminology.yaml", "terms"), ("sources.yaml", "sources"), ("hypotheses.yaml", "hypotheses")):
        (research_dir / "knowledge" / name).write_text(f"{key}: []\n", encoding="utf-8")

    result = build_research_database([episode_path], research_dir=research_dir)
    assert result.experiments == 1
    assert result.observations == 2
    with sqlite3.connect(result.database) as conn:
        metrics = json.loads(conn.execute("SELECT metrics_json FROM experiments").fetchone()[0])
    assert metrics["attack_added_security_event_episodes"] == 1
    assert metrics["off_objective_security_event_episodes"] == 1
    assert metrics["paired_utility"]["success_failure"] == 1
    assert metrics["paired_utility"]["success_success"] == 1


def test_repository_research_knowledge_loads_and_is_queryable(tmp_path: Path):
    result = build_research_database([], research_dir=ROOT / "research", database=tmp_path / "research.sqlite")
    summary = research_summary(result.database)
    assert summary["counts"]["claims"] >= 10
    assert summary["counts"]["hypotheses"] >= 5
    hits = research_query(result.database, "model is not the security boundary")
    assert any(item.get("id") == "CLAIM-VAIS-001" for item in hits)
    hyp_hits = research_query(result.database, "fixed-seed mutation search")
    assert any(item.get("id") == "HYP-001" and item.get("table") == "hypotheses" for item in hyp_hits)


def test_compact_history_version_names_normalize_as_minor_releases():
    from vais.research import _normalize_version

    assert _normalize_version("F:/vais-v03") == "0.3.0"
    assert _normalize_version("F:/vais-v09") == "0.9.0"
    assert _normalize_version("F:/vais-v0.10") == "0.10.0"


def test_root_project_metadata_overrides_compact_folder_name(tmp_path: Path):
    from vais.research import _detect_root_version

    root = tmp_path / "vais-v09"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="x"\nversion="0.9.3"\n', encoding="utf-8")
    assert _detect_root_version(root) == "0.9.3"


def test_compact_experiment_filename_versions_normalize():
    from vais.research import _normalize_version

    assert _normalize_version("qwen35-v050.jsonl") == "0.5.0"
    assert _normalize_version("qwen35-v080-mcp.jsonl") == "0.8.0"
    assert _normalize_version("qwen35-reference-v093.jsonl") == "0.9.3"
    assert _normalize_version("qwen35-adaptive-v010.jsonl") == "0.10.0"


def _empty_research_knowledge(research_dir: Path) -> None:
    (research_dir / "knowledge").mkdir(parents=True, exist_ok=True)
    for name, key in (
        ("claims.yaml", "claims"),
        ("findings.yaml", "findings"),
        ("decisions.yaml", "decisions"),
        ("limitations.yaml", "limitations"),
        ("terminology.yaml", "terms"),
        ("sources.yaml", "sources"),
        ("hypotheses.yaml", "hypotheses"),
    ):
        (research_dir / "knowledge" / name).write_text(f"{key}: []\n", encoding="utf-8")


def test_research_summary_distinguishes_archive_instances_from_content(tmp_path: Path):
    from vais.research import research_doctor

    first = tmp_path / "a" / "same.jsonl"
    second = tmp_path / "b" / "same-copy.jsonl"
    first.parent.mkdir()
    second.parent.mkdir()
    row = {
        "framework_version": "0.10.0",
        "target_id": "lmstudio:qwen/test",
        "workflow_id": "attack-01",
        "episode": 1,
        "reward_evaluated": True,
        "terminal_security_reward": 0.0,
        "protected_violation": False,
        "pair_delta": {"added_security_events": []},
        "control_result": {"target_failure": False, "workflow_utility_success": True},
        "protected_result": {"target_failure": False, "attack_objective_success": False, "workflow_utility_success": True},
    }
    content = json.dumps(row) + "\n"
    first.write_text(content, encoding="utf-8")
    second.write_text(content, encoding="utf-8")
    research_dir = tmp_path / "research"
    _empty_research_knowledge(research_dir)

    result = build_research_database([first, second], research_dir=research_dir)
    summary = research_summary(result.database)
    inv = summary["content_inventory"]
    assert inv["artifact_instances"] == 2
    assert inv["unique_artifact_contents"] == 1
    assert inv["experiment_records"] == 2
    assert inv["content_addressed_experiments"] == 1
    assert inv["observation_records"] == 2
    assert inv["content_addressed_observations"] == 1

    doctor = research_doctor(result.database)
    assert doctor["content_inventory"]["duplicate_artifact_instances"] == 1
    assert doctor["content_inventory"]["duplicate_artifact_groups"] == 1
    assert doctor["ok"] is True


def test_research_doctor_distinguishes_expected_external_from_integrity_failure(tmp_path: Path):
    from vais.research import research_doctor

    research_dir = tmp_path / "research"
    _empty_research_knowledge(research_dir)
    (research_dir / "knowledge" / "sources.yaml").write_text(
        "sources:\n"
        "  - id: SRC-EXT\n"
        "    title: External manuscript\n"
        "    source_type: manuscript\n"
        "    artifact_name: manuscript.pdf\n"
        "    sha256: deadbeef\n"
        "    ingestion_status: artifact_expected_external\n",
        encoding="utf-8",
    )
    result = build_research_database([], research_dir=research_dir)
    doctor = research_doctor(result.database)
    assert doctor["evidence_integrity"]["expected_external_unresolved"] == 1
    assert doctor["evidence_integrity"]["unexpected_unresolved"] == 0
    assert doctor["ok"] is True


def test_research_doctor_flags_evidence_less_supported_claim(tmp_path: Path):
    from vais.research import research_doctor

    research_dir = tmp_path / "research"
    _empty_research_knowledge(research_dir)
    (research_dir / "knowledge" / "claims.yaml").write_text(
        "claims:\n"
        "  - id: CLAIM-X\n"
        "    status: supported\n"
        "    claim: Test claim\n"
        "    evidence: [missing.json]\n",
        encoding="utf-8",
    )
    result = build_research_database([], research_dir=research_dir)
    doctor = research_doctor(result.database)
    assert doctor["evidence_integrity"]["unexpected_unresolved"] == 1
    assert doctor["knowledge_integrity"]["supported_claims_without_resolved_evidence"] == ["CLAIM-X"]
    assert doctor["ok"] is False
