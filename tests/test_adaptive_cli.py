import json
from pathlib import Path

from vais.cli import main


def test_adaptive_default_cli_writes_episode_summary_and_rlvr(tmp_path: Path):
    output = tmp_path / "episodes.jsonl"
    summary = tmp_path / "summary.json"
    rlvr = tmp_path / "rlvr.jsonl"
    rc = main(
        [
            "adaptive-reference-default",
            "--episodes",
            "3",
            "--scenario",
            "attack-03",
            "--output",
            str(output),
            "--summary",
            str(summary),
            "--rlvr-output",
            str(rlvr),
        ]
    )
    assert rc == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 3
    assert len(rlvr.read_text(encoding="utf-8").splitlines()) == 3
    data = json.loads(summary.read_text(encoding="utf-8"))
    assert data["framework_version"] == "0.12.0rc7"
    assert data["reference_baseline_version"] == "0.9.3"
    target = data["by_target"]["deterministic-adaptive-pattern"]
    assert target["terminal_reward_one_count"] == 0
    assert target["evaluable_episodes"] == 3


def test_adaptive_cli_refuses_to_overwrite_before_running(tmp_path: Path, capsys):
    output = tmp_path / "episodes.jsonl"
    summary = tmp_path / "summary.json"
    rlvr = tmp_path / "rlvr.jsonl"
    output.write_text("keep\n", encoding="utf-8")

    rc = main(
        [
            "adaptive-reference-default",
            "--episodes", "1",
            "--scenario", "attack-03",
            "--output", str(output),
            "--summary", str(summary),
            "--rlvr-output", str(rlvr),
        ]
    )

    assert rc == 6
    assert output.read_text(encoding="utf-8") == "keep\n"
    assert not summary.exists()
    assert not rlvr.exists()
    assert "refusing to overwrite" in capsys.readouterr().out


def test_adaptive_cli_overwrite_is_explicit_opt_in(tmp_path: Path):
    output = tmp_path / "episodes.jsonl"
    summary = tmp_path / "summary.json"
    rlvr = tmp_path / "rlvr.jsonl"
    output.write_text("replace\n", encoding="utf-8")

    rc = main(
        [
            "adaptive-reference-default",
            "--episodes", "1",
            "--scenario", "attack-03",
            "--output", str(output),
            "--summary", str(summary),
            "--rlvr-output", str(rlvr),
            "--overwrite",
        ]
    )

    assert rc == 0
    assert output.read_text(encoding="utf-8") != "replace\n"
