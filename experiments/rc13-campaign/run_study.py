"""Run the RC13 campaign's arms in pre-registered order. Resumable; see PREREGISTRATION.md.

Usage, from the repository root, with LM Studio's server running:

    .venv\\Scripts\\python.exe experiments\\rc13-campaign\\run_study.py
    .venv\\Scripts\\python.exe experiments\\rc13-campaign\\run_study.py --dry-run
    .venv\\Scripts\\python.exe experiments\\rc13-campaign\\run_study.py --arm phi-4-outcomes

This is P1b-4's runner with one change: each arm names the attacker's feedback (reasons or
outcomes) and passes it as --attacker-feedback, and it decodes the lms CLI's output as UTF-8.
Gates, stages and resumption are P1b-4's.

Finished arms (complete, gate_failed, nonconforming) are skipped on the next invocation. An arm
that stopped on an infrastructure error is run again from its beginning, and the attempt is
counted in results/state.json so it can be logged as a deviation. The run stops at the first
infrastructure error rather than failing every later arm the same way.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
STUDY_DIR = Path(__file__).resolve().parent
RESULTS = STUDY_DIR / "results"
FINAL = {"complete", "gate_failed", "nonconforming"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    line = f"[{now()}] {message}"
    print(line, flush=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    with (RESULTS / "run.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def keep_awake(enable: bool) -> None:
    """Stop Windows sleeping while arms run. No effect elsewhere."""
    if sys.platform != "win32":
        return
    import ctypes
    ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
    flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if enable else 0)
    ctypes.windll.kernel32.SetThreadExecutionState(flags)


def lms_path() -> str:
    found = shutil.which("lms")
    if found:
        return found
    fallback = Path.home() / ".lmstudio" / "bin" / ("lms.exe" if sys.platform == "win32" else "lms")
    if fallback.exists():
        return str(fallback)
    raise SystemExit("cannot find the LM Studio 'lms' CLI")


def lms(*args: str, capture: bool = True) -> str:
    # lms prints UTF-8 (spinners, model names); the Windows default code page cannot decode it.
    result = subprocess.run([lms_path(), *args], capture_output=capture, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(f"lms {' '.join(args)} failed: {(result.stderr or result.stdout or '').strip()}")
    return result.stdout or ""


def git_commit() -> str:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "src", "experiments/rc13-campaign"],
                           cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return head + ("+dirty" if dirty else "")


def load_models(study: dict, arm: dict) -> list[dict]:
    runtime, attacker = study["runtime"], study["attacker"]
    lms("unload", "--all")
    lms("load", arm["model_key"], "--identifier", arm["identifier"], "--context-length",
        str(runtime["context_length"]), "--gpu", runtime["gpu"], "--parallel", str(runtime["parallel"]), "--yes")
    lms("load", attacker["model_key"], "--identifier", attacker["identifier"], "--context-length",
        str(attacker["context_length"]), "--gpu", runtime["gpu"], "--parallel", str(runtime["parallel"]), "--yes")
    loaded = [m for m in json.loads(lms("ps", "--json")) if m.get("type") == "llm"]
    expected = {
        arm["identifier"]: (arm["model_key"], runtime["context_length"]),
        attacker["identifier"]: (attacker["model_key"], attacker["context_length"]),
    }
    observed = {m.get("identifier"): (m.get("modelKey"), m.get("contextLength")) for m in loaded}
    if observed != expected:
        raise RuntimeError(f"loaded models differ from the study: expected {expected}, observed {observed}")
    return loaded


def stage_command(study: dict, arm: dict, stage: str, out: Path) -> list[str]:
    runtime, attacker, target = study["runtime"], study["attacker"], study["target"]
    config = study[stage]
    argv = [
        sys.executable, "-m", "vais", "adaptive-reference-lmstudio",
        "--target-model", arm["identifier"],
        "--target-reasoning-mode", arm["reasoning"],
        "--target-temperature", str(target["temperature"]),
        "--target-max-tokens", str(target["max_tokens"]),
        "--target-truncation-retry-tokens", str(target["truncation_retry_tokens"]),
        "--attacker-model", attacker["identifier"],
        "--attacker-reasoning-mode", attacker["reasoning_mode"],
        "--attacker-disable-thinking",
        "--attacker-temperature", str(attacker["temperature"]),
        "--attacker-max-tokens", str(attacker["max_tokens"]),
        "--attacker-feedback", arm["feedback"],
        "--target-base-url", runtime["base_url"],
        "--timeout", str(runtime["timeout_seconds"]),
        "--transport-retries", str(runtime["transport_retries"]),
        "--episodes", str(config["episodes"]),
        "--output", str(out / f"{stage}.jsonl"),
        "--summary", str(out / f"{stage}-summary.json"),
        "--rlvr-output", str(out / f"{stage}-rlvr.jsonl"),
        "--overwrite",
        "--fail-on-reasoning-mode-mismatch",
    ]
    if arm["reasoning"] == "off":
        argv.append("--target-disable-thinking")
    if arm.get("request_reasoning"):
        argv.append("--target-enable-thinking")
    if config["scenarios"] != "all_20":
        for scenario in config["scenarios"]:
            argv += ["--scenario", scenario]
    return argv


def run_stage(study: dict, arm: dict, stage: str, out: Path, dry_run: bool) -> tuple[int, dict | None, float]:
    argv = stage_command(study, arm, stage, out)
    log(f"{arm['id']} {stage}: {' '.join(argv[2:])}")
    if dry_run:
        return 0, None, 0.0
    started = time.monotonic()
    with (out / f"{stage}.log").open("w", encoding="utf-8") as fh:
        code = subprocess.run(argv, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT).returncode
    elapsed = time.monotonic() - started
    summary_path = out / f"{stage}-summary.json"
    summary = None
    if summary_path.exists():
        data = json.loads(summary_path.read_text(encoding="utf-8"))
        targets = data.get("by_target") or {}
        summary = next(iter(targets.values())) if len(targets) == 1 else None
    return code, summary, elapsed


def artifacts(out: Path, stage: str) -> dict:
    return {name: sha256(out / name) for name in (f"{stage}.jsonl", f"{stage}-summary.json", f"{stage}-rlvr.jsonl")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--arm", action="append", help="run only these arm ids")
    args = parser.parse_args()

    study = json.loads((STUDY_DIR / "study.json").read_text(encoding="utf-8"))
    RESULTS.mkdir(parents=True, exist_ok=True)
    state_path = RESULTS / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {"arms": {}}

    def save() -> None:
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(state_path)

    arms = [a for a in study["arms"] if not args.arm or a["id"] in args.arm]
    commit = git_commit()
    log(f"study start, commit {commit}, {len(arms)} arm(s) selected, dry_run={args.dry_run}")
    keep_awake(True)
    try:
        for arm in arms:
            record = state["arms"].setdefault(arm["id"], {"attempts": 0})
            if record.get("status") in FINAL:
                log(f"{arm['id']}: already {record['status']}, skipping")
                continue
            out = RESULTS / arm["id"]
            out.mkdir(parents=True, exist_ok=True)
            record.update(attempts=record["attempts"] + (0 if args.dry_run else 1), commit=commit, started=now())
            if not args.dry_run:
                try:
                    loaded = load_models(study, arm)
                except RuntimeError as exc:
                    record.update(status="error", error=str(exc), finished=now())
                    save()
                    log(f"{arm['id']}: model load failed, stopping the run: {exc}")
                    return 2
                (out / "environment.json").write_text(json.dumps({"loaded": loaded, "commit": commit, "at": now()},
                                                                 indent=2, sort_keys=True) + "\n", encoding="utf-8")

            code, summary, elapsed = run_stage(study, arm, "qualification", out, args.dry_run)
            if args.dry_run:
                run_stage(study, arm, "full", out, True)
                continue
            record["qualification"] = {"exit": code, "seconds": round(elapsed, 1), "summary": summary,
                                       "artifacts": artifacts(out, "qualification")}
            if summary is None:
                record.update(status="error", error=f"qualification produced no summary (exit {code})", finished=now())
                save()
                log(f"{arm['id']}: qualification produced no summary, stopping the run")
                return 2
            reasons = []
            if (summary.get("evaluable_episodes") or 0) < 1:
                reasons.append("no evaluable episode")
            if summary.get("reasoning_mode_mismatch"):
                reasons.append("reasoning mode mismatch")
            if (summary.get("attacker_generation_failures") or 0) >= (summary.get("episodes") or 0):
                reasons.append("attacker produced no valid candidate")
            if reasons:
                status = "nonconforming" if summary.get("reasoning_mode_mismatch") else "gate_failed"
                record.update(status=status, gate_reasons=reasons, finished=now())
                save()
                log(f"{arm['id']}: {status} at qualification: {reasons}")
                continue
            save()

            code, summary, elapsed = run_stage(study, arm, "full", out, False)
            record["full"] = {"exit": code, "seconds": round(elapsed, 1), "summary": summary,
                              "artifacts": artifacts(out, "full")}
            if summary is not None and summary.get("reasoning_mode_mismatch"):
                record.update(status="nonconforming", finished=now())
                save()
                log(f"{arm['id']}: nonconforming in the full stage")
                continue
            if code != 0 or summary is None:
                record.update(status="error", error=f"full stage exit {code}", finished=now())
                save()
                log(f"{arm['id']}: full stage failed (exit {code}), stopping the run; see {out / 'full.log'}")
                return 2
            record.update(status="complete", finished=now())
            save()
            log(f"{arm['id']}: complete in {elapsed / 3600:.2f} h; evaluable {summary.get('evaluable_episodes')}, "
                f"violations {summary.get('terminal_reward_one_count')}, "
                f"attack-added {summary.get('attack_added_security_event_episodes')}")
    finally:
        keep_awake(False)
        if not args.dry_run:
            try:
                lms("unload", "--all")
            except RuntimeError as exc:
                log(f"unload at exit failed: {exc}")
    log("study run finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
