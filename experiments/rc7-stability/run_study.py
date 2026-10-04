"""Run the RC7 stability study (PREREGISTRATION.md). Resumable.

From the repository root, with LM Studio's server running:

    python experiments\\rc7-stability\\run_study.py --part A --dry-run
    python experiments\\rc7-stability\\run_study.py --part A          # night 1: the whole panel
    python experiments\\rc7-stability\\run_study.py --part B          # night 2: repeatability
    python experiments\\rc7-stability\\run_study.py --part C          # night 2: RC7's probable engine

Each model's full stage is RC7's command from ``benchmarks/rc/full-plan.ps1``. Before it runs, the
model is loaded exactly as RC7 loaded it and its environment is recorded: the LM Studio version,
the selected engine, the loaded configuration, and the model file's size, date and SHA-256.
Part C selects ``ENGINE_C`` for its runs and restores the previously selected engine afterwards,
whatever happens. Finished models are skipped on the next invocation; one that stopped on an
infrastructure error is run again and the attempt counted.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
STUDY_DIR = Path(__file__).resolve().parent
PARTS = {"A": None, "B": ("qwen3-0.6b", "lfm2.5-1.2b-instruct", "qwen2.5-7b-instruct"),
         "C": ("qwen3-0.6b", "lfm2.5-1.2b-instruct", "qwen2.5-7b-instruct")}
ENGINE_C = "llama.cpp-win-x86_64-nvidia-cuda-avx2@2.5.1"
MODELS_DIR = Path.home() / ".lmstudio" / "models"
HUB_DIR = Path.home() / ".lmstudio" / "hub" / "models"
FINAL = {"complete"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Run:
    def __init__(self, results: Path) -> None:
        self.results = results
        results.mkdir(parents=True, exist_ok=True)

    def log(self, message: str) -> None:
        line = f"[{now()}] {message}"
        print(line, flush=True)
        with (self.results / "run.log").open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def lms_path() -> str:
    found = shutil.which("lms")
    fallback = Path.home() / ".lmstudio" / "bin" / ("lms.exe" if sys.platform == "win32" else "lms")
    if found:
        return found
    if fallback.exists():
        return str(fallback)
    raise SystemExit("cannot find the LM Studio 'lms' CLI")


def lms(*args: str) -> str:
    result = subprocess.run([lms_path(), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(f"lms {' '.join(args)} failed: {(result.stderr or result.stdout or '').strip()[:400]}")
    return result.stdout or ""


def selected_engine() -> str:
    for line in lms("runtime", "ls").splitlines():
        if "✓" in line:
            return line.split()[0]
    raise RuntimeError("no selected LLM engine in 'lms runtime ls'")


def keep_awake(enable: bool) -> None:
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | (0x00000001 if enable else 0))


def sha256_of(path: Path) -> tuple[str, int]:
    """The SHA-256 of a model file, or of a model directory's files in name order."""
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    digest, size = hashlib.sha256(), 0
    for f in files:
        if path.is_dir():
            digest.update(str(f.relative_to(path)).replace("\\", "/").encode("utf-8") + b"\0")
        with f.open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 22), b""):
                digest.update(block)
                size += len(block)
    return digest.hexdigest(), size


def catalog_sha256(hub: Path) -> tuple[str, int, list[str]]:
    """A catalog model: its hub entry plus the GGUF folder its manifest names.

    LM Studio lists a catalog model under the hub directory; the weights sit in the folder of a
    Hugging Face source named in the entry's manifest, and the listed size is the entry's files
    plus that folder's. Each file is hashed preceded by its name, in name order.
    """
    manifest = json.loads((hub / "manifest.json").read_text(encoding="utf-8"))
    folders = [MODELS_DIR / src["user"] / src["repo"]
               for dep in manifest.get("dependencies", []) for src in dep.get("sources", [])
               if src.get("type") == "huggingface" and src.get("repo", "").lower().endswith("-gguf")
               and (MODELS_DIR / src["user"] / src["repo"]).is_dir()]
    files = [("hub/" + str(f.relative_to(HUB_DIR)).replace("\\", "/"), f) for f in hub.rglob("*") if f.is_file()]
    for folder in folders:
        files += [(str(f.relative_to(MODELS_DIR)).replace("\\", "/"), f) for f in folder.rglob("*") if f.is_file()]
    digest, size = hashlib.sha256(), 0
    for name, f in sorted(files):
        digest.update(name.encode("utf-8") + b"\0")
        with f.open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 22), b""):
                digest.update(block)
                size += len(block)
    return digest.hexdigest(), size, [name for name, _ in sorted(files)]


def environment(study: dict, arm: dict) -> dict:
    runtime = study["runtime"]
    lms("unload", "--all")
    lms("load", arm["model_key"], "--identifier", arm["lmstudio_model"], "--context-length", str(runtime["context_length"]),
        "--gpu", runtime["gpu"], "--parallel", str(runtime["parallel"]), "--yes")
    loaded = [m for m in json.loads(lms("ps", "--json")) if m.get("type") == "llm"]
    if [(m.get("identifier"), m.get("modelKey"), m.get("contextLength")) for m in loaded] != [
            (arm["lmstudio_model"], arm["model_key"], runtime["context_length"])]:
        raise RuntimeError(f"loaded models differ from the study: {loaded}")
    listed = next(m for m in json.loads(lms("ls", "--json")) if m.get("modelKey") == arm["model_key"])
    path = MODELS_DIR / listed["path"]
    # The hash identifies the model from now on; failing to compute it is recorded, not fatal.
    files, problem, modified = None, None, None
    try:
        if path.exists():
            digest, hashed_bytes = sha256_of(path)
            modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        else:
            path = HUB_DIR / listed["path"]
            digest, hashed_bytes, files = catalog_sha256(path)
    except (OSError, ValueError, KeyError) as exc:
        digest, hashed_bytes, problem = None, None, f"{type(exc).__name__}: {exc}"[:300]
    return {
        "at": now(), "lms_version": re.sub(r"\x1b\[[0-9;]*m", "", lms("version")).strip()[-200:],
        "engine": selected_engine(), "loaded": loaded, "listed": listed,
        "model_file": {"path": str(path), "sha256": digest, "hashed_bytes": hashed_bytes, "files": files,
                       "hash_problem": problem, "size_bytes": listed.get("sizeBytes"),
                       "hashed_bytes_match_listed": hashed_bytes == listed.get("sizeBytes"),
                       "modified": modified,
                       "rc7_size_bytes": arm["rc7_size_bytes"],
                       "changed_since_rc7": listed.get("sizeBytes") != arm["rc7_size_bytes"]},
    }


def command(study: dict, arm: dict, out: Path) -> list[str]:
    """RC7's full-stage command (benchmarks/rc/full-plan.ps1), with this study's output paths."""
    r = study["runtime"]
    argv = [sys.executable, "-m", "vais", "adaptive-reference-lmstudio", "--target-model", arm["lmstudio_model"],
            "--target-reasoning-mode", arm["reasoning"]]
    if arm["disable_thinking"]:
        argv.append("--target-disable-thinking")
    return argv + ["--episodes", str(r["episodes"]), "--target-truncation-retry-tokens", str(r["truncation_retry_tokens"]),
                   "--output", str(out / "full.jsonl"), "--summary", str(out / "full-summary.json"),
                   "--rlvr-output", str(out / "full-rlvr.jsonl"), *study["flags"]]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--part", required=True, choices=sorted(PARTS))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--results", help="write results here instead of results/<part>")
    args = parser.parse_args()
    study = json.loads((STUDY_DIR / "study.json").read_text(encoding="utf-8"))
    run = Run(Path(args.results).resolve() if args.results else STUDY_DIR / "results" / args.part)
    arms = [a for a in study["arms"] if PARTS[args.part] is None or a["id"] in PARTS[args.part]]
    state_path = run.results / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {"part": args.part, "arms": {}}

    def save() -> None:
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(state_path)

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "src", "experiments/rc7-stability"],
                           cwd=ROOT, capture_output=True, text=True).stdout.strip()
    commit = head + ("+dirty" if dirty else "")
    run.log(f"part {args.part} start, commit {commit}, {len(arms)} model(s), dry_run={args.dry_run}")
    previous_engine = None
    keep_awake(True)
    try:
        if args.part == "C" and not args.dry_run:
            previous_engine = selected_engine()
            lms("runtime", "select", ENGINE_C)
            if selected_engine() != ENGINE_C:
                raise RuntimeError(f"could not select {ENGINE_C}")
            run.log(f"engine {ENGINE_C} selected for part C (was {previous_engine})")
        for arm in arms:
            record = state["arms"].setdefault(arm["id"], {"attempts": 0})
            if record.get("status") in FINAL:
                run.log(f"{arm['id']}: already complete, skipping")
                continue
            out = run.results / arm["id"]
            out.mkdir(parents=True, exist_ok=True)
            argv = command(study, arm, out)
            run.log(f"{arm['id']}: {' '.join(argv[2:])}")
            if args.dry_run:
                continue
            record.update(attempts=record["attempts"] + 1, commit=commit, started=now())
            try:
                env = environment(study, arm)
            except (RuntimeError, StopIteration) as exc:
                record.update(status="error", error=str(exc)[:500], finished=now())
                save()
                run.log(f"{arm['id']}: could not load or record the model, stopping: {exc}")
                return 2
            (out / "environment.json").write_text(json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            started = time.monotonic()
            with (out / "full.log").open("w", encoding="utf-8") as fh:
                env_vars = {**os.environ, "PYTHONPATH": str(ROOT / "src")}  # this checkout's VAIS
                code = subprocess.run(argv, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, env=env_vars).returncode
            episodes = sum(1 for line in (out / "full.jsonl").open(encoding="utf-8") if line.strip()) \
                if (out / "full.jsonl").exists() else 0
            record.update(exit=code, episodes=episodes, seconds=round(time.monotonic() - started, 1), finished=now(),
                          engine=env["engine"], model_file_changed=env["model_file"]["changed_since_rc7"])
            # A --fail-on-* flag exits non-zero after a complete run (as RC7's gate did for smollm3);
            # only a run that did not write every episode is an error.
            record["status"] = "complete" if episodes == study["runtime"]["episodes"] * 20 else "error"
            save()
            run.log(f"{arm['id']}: {record['status']} in {record['seconds'] / 60:.1f} min, exit {code}, "
                    f"{episodes} episodes, engine {env['engine']}, file changed: {env['model_file']['changed_since_rc7']}")
            if record["status"] == "error":
                run.log(f"{arm['id']}: incomplete, stopping; see {out / 'full.log'}")
                return 2
    finally:
        if previous_engine is not None:
            try:
                lms("runtime", "select", previous_engine)
                run.log(f"engine restored to {previous_engine}")
            except RuntimeError as exc:
                run.log(f"COULD NOT RESTORE ENGINE {previous_engine}: {exc}")
        keep_awake(False)
        if not args.dry_run:
            try:
                lms("unload", "--all")
            except RuntimeError as exc:
                run.log(f"unload at exit failed: {exc}")
    run.log(f"part {args.part} finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
