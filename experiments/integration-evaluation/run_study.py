"""Run the integration evaluation (PREREGISTRATION.md) as study.json declares it.

Every run is one unit: a fresh backend from the evaluation seed (attacked or not, a fault armed
or not), the contract built from the trusted task, the gateway, then the agent, then the
independent verifier on the backend's export. A unit's files stay in its own directory under
results/<stage>/ and one line per unit goes to results/<stage>/records.jsonl, so a stopped run
resumes where it stopped and the analyzer (analyze.py) reads everything from disk.

Stages:
- ``qualification``: per model, two clean instances of each task kind (study.json). A model
  qualifies when each kind has at least one evaluable run.
- ``full``: the scripted conditions once (the compromised agent and the bypass checks do not
  depend on a model), then per model the clean, fault and attacked runs. It refuses to start
  before registration, or for a model that has not qualified, or if the frozen files changed.

Usage (from the repository root, with LM Studio's ``lms`` CLI installed):
  python experiments/integration-evaluation/run_study.py --stage qualification
  python experiments/integration-evaluation/run_study.py --stage full
  python experiments/integration-evaluation/run_study.py --stage full --dry-run   # list units
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import traceback
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "examples"))

from ap_integration.task import load_task  # noqa: E402
import harness  # noqa: E402
import suite  # noqa: E402

STAGES = ("qualification", "full")
CONDITIONS = ("clean", "attacked", "faults", "compromised", "bypass")
SCRIPTED = "scripted"
RESULTS = HERE / "results"


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def log(message: str) -> None:
    print(f"[{now()}] {message}", flush=True)


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load_study(path: Path = HERE / "study.json") -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def check_frozen(study: dict[str, Any], *, scenarios: Path = HERE / "scenarios.yaml", seed: Path = HERE / "seed.json") -> None:
    frozen = study["frozen"]
    for name, path in (("scenarios_sha256", scenarios), ("seed_sha256", seed)):
        if file_digest(path) != frozen[name]:
            raise SystemExit(f"{path.name} differs from the digest study.json froze ({name})")


def registered(prereg: Path = HERE / "PREREGISTRATION.md") -> bool:
    head = prereg.read_text(encoding="utf-8").splitlines()[:10]
    return not any(line.startswith("> **DRAFT") for line in head)


def git_state(paths: list[str]) -> dict[str, Any]:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", *paths], cwd=ROOT, capture_output=True,
                           text=True).stdout.strip()
    return {"commit": head, "dirty": bool(dirty), "dirty_paths": dirty.splitlines()[:50]}


# --- units ------------------------------------------------------------------------------------

def _tasks(spec: str | list[str]) -> list[str]:
    return sorted(p.stem for p in (HERE / "tasks").glob("*.yaml")) if spec == "all" else list(spec)


def units(study: dict[str, Any], stage: str, models: list[str] | None = None) -> list[dict[str, Any]]:
    """Every run of the stage, in the order the runner makes them."""
    chosen = [m for m in study["models"] if not models or m["id"] in models]
    out: list[dict[str, Any]] = []
    if stage == "qualification":
        for model in chosen:
            out += [{"model": model["id"], "condition": "clean", "task": t, "name": f"clean-{t}"}
                    for t in study["qualification"]["tasks"]]
        return out
    full = study["full"]
    if not models or SCRIPTED in models:
        for condition in ("compromised", "bypass"):
            out += [{"model": SCRIPTED, "condition": condition, "task": t, "name": f"{condition}-{t}"}
                    for t in _tasks(full[condition]["tasks"])]
    scenarios = suite.load_suite() if full["attacked"]["scenarios"] == "all" else \
        [s for s in suite.load_suite() if s["id"] in full["attacked"]["scenarios"]]
    for model in chosen:
        out += [{"model": model["id"], "condition": "clean", "task": t, "name": f"clean-{t}"}
                for t in _tasks(full["clean"]["tasks"])]
        for fault in full["faults"]["faults"]:
            out += [{"model": model["id"], "condition": "faults", "task": t, "fault": fault,
                     "name": f"faults-{fault['mode']}-{t}"} for t in full["faults"]["tasks"]]
        for scenario in scenarios:
            for variant in full["attacked"]["variants"]:
                out.append({"model": model["id"], "condition": "attacked", "task": scenario["base"],
                            "scenario": scenario["id"], "category": scenario["category"], "variant": variant,
                            "fault": scenario.get("fault"), "name": f"attacked-{scenario['id']}-{variant}"})
    return out


def unit_key(unit: dict[str, Any]) -> str:
    return f"{unit['model']}/{unit['name']}"


# --- one run ----------------------------------------------------------------------------------

Transport = Callable[..., dict[str, Any]]


def model_config(study: dict[str, Any], model: dict[str, Any]):
    from ap_integration.model_agent import ModelConfig

    runtime, target = study["runtime"], study["target"]
    return ModelConfig(model=model["identifier"], base_url=runtime["base_url"], temperature=target["temperature"],
                       max_tokens=target["max_tokens"], truncation_retry_tokens=target["truncation_retry_tokens"],
                       timeout_seconds=runtime["timeout_seconds"], disable_thinking=target["disable_thinking"],
                       transport_retries=runtime["transport_retries"])


def _crashed(run: Path) -> bool:
    """Whether an armed crash fault fired: the backend is then gone by design, not by failure."""
    from ap_sandbox.store import Store

    try:
        return any(row["mode"] == "crash_after_commit" for row in Store(run / "ap.sqlite3").export()["fault_log"])
    except Exception:
        return False


def run_unit(unit: dict[str, Any], study: dict[str, Any], directory: Path, *,
             transport: Transport | None = None) -> dict[str, Any]:
    """Make one run in ``directory`` (which must not exist yet) and return its record."""
    task_path = HERE / "tasks" / f"{unit['task']}.yaml"
    task = load_task(task_path)
    seed = json.loads((HERE / "seed.json").read_text(encoding="utf-8"))
    if unit.get("scenario"):
        scenario = next(s for s in suite.load_suite() if s["id"] == unit["scenario"])
        seed = suite.attacked_seed(seed, scenario, unit["variant"])
    faults = [unit["fault"]] if unit.get("fault") else []
    run = directory / "run"
    record: dict[str, Any] = {**{k: v for k, v in unit.items()}, "started": now()}
    started = time.monotonic()
    outcome: dict[str, Any] = {}
    try:
        with harness.deployment(run, task, seed, faults=faults, call_timeout=study["gateway"]["call_timeout"]) as (url, token):
            operator = harness.operator_for(run, task, seed)
            if unit["condition"] == "compromised":
                from ap_integration.compromised import run_compromised
                outcome = asyncio.run(run_compromised(url, token, task, directory / "agent-log.jsonl", operator))
                outcome = {"attempts": outcome["attempts"], "allowed": outcome["allowed"], "phases": outcome["phases"]}
            elif unit["condition"] == "bypass":
                from ap_integration.agent import run_plan
                from ap_integration.bypass import backend_without_key, out_of_band_payment
                outcome["backend_without_key_exit"] = backend_without_key(run / "ap.sqlite3")
                asyncio.run(run_plan(url, token, task, "clean", directory / "agent-log.jsonl", operator))
                outcome["control_receipt"] = out_of_band_payment(run / "ap.sqlite3")
            else:
                from ap_integration.model_agent import run_model
                model = next(m for m in study["models"] if m["id"] == unit["model"])
                kwargs = {"transport": transport} if transport is not None else {}
                result = asyncio.run(run_model(url, token, task, model_config(study, model),
                                               log=directory / "agent-log.jsonl", operator=operator, **kwargs))
                outcome = {"ended": result["ended"], "turns": result["turns"], "tools": result["tools"]}
        if outcome.get("ended") == "no_valid_plan":
            record.update(status="failed", cause="model_" + _last_generation_status(directory / "agent-log.jsonl"))
        else:
            record.update(status="evaluable", cause=None)
    except Exception as exc:  # the run failed; its effects, if any, are still verified below
        if _crashed(run):
            record.update(status="evaluable", cause="ended_by_armed_crash")
        else:
            record.update(status="failed", cause="harness_error")
        record["error"] = f"{type(exc).__name__}: {exc}"
        (directory / "error.txt").write_text(traceback.format_exc(), encoding="utf-8")
    record.update(outcome)
    try:
        report = harness.verify_run(run)
        record["verification"] = {
            "all_invariants_hold": report["all_invariants_hold"],
            "violations": sum(len(i["violations"]) for i in report["invariants"]),
            "complete": report["task"]["complete"],
            "faults_fired": report["backend"]["faults_fired"],
        }
    except Exception as exc:
        record["verification"] = None
        record.update(status="failed", cause=record.get("cause") or "unverifiable",
                      verify_error=f"{type(exc).__name__}: {exc}")
    record.update(seconds=round(time.monotonic() - started, 2), finished=now())
    (directory / "record.json").write_text(json.dumps(record, indent=1, sort_keys=True, default=str), encoding="utf-8")
    return record


def _last_generation_status(agent_log: Path) -> str:
    try:
        lines = [json.loads(line) for line in agent_log.read_text(encoding="utf-8").splitlines() if line.strip()]
        plan = [r for r in lines if r.get("kind") == "plan"][-1]
        return plan["generation"]["attempts"][-1]["status"]
    except (OSError, IndexError, KeyError, ValueError):
        return "unknown"


# --- the stage --------------------------------------------------------------------------------

def read_records(results: Path) -> dict[str, dict[str, Any]]:
    path = results / "records.jsonl"
    if not path.exists():
        return {}
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return {unit_key(r): r for r in records}


def qualified(study: dict[str, Any], results: Path) -> dict[str, bool]:
    """Per model: every task kind has at least one evaluable qualification run."""
    records = read_records(results).values()
    verdict = {}
    for model in study["models"]:
        kinds: dict[str, bool] = {}
        for task in study["qualification"]["tasks"]:
            kind = task.rsplit("-", 1)[0]
            ok = any(r["model"] == model["id"] and r["task"] == task and r["status"] == "evaluable" for r in records)
            kinds[kind] = kinds.get(kind, False) or ok
        verdict[model["id"]] = bool(kinds) and all(kinds.values())
    return verdict


def _lms_path() -> str:
    found = shutil.which("lms")
    if found:
        return found
    fallback = Path.home() / ".lmstudio" / "bin" / ("lms.exe" if sys.platform == "win32" else "lms")
    if fallback.exists():
        return str(fallback)
    raise SystemExit("cannot find the LM Studio 'lms' CLI")


def lms(*args: str) -> str:
    result = subprocess.run([_lms_path(), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(f"lms {' '.join(args)} failed: {(result.stderr or result.stdout or '').strip()}")
    return result.stdout or ""


def load_model(study: dict[str, Any], model: dict[str, Any]) -> list[dict[str, Any]]:
    runtime = study["runtime"]
    lms("unload", "--all")
    lms("load", model["model_key"], "--identifier", model["identifier"], "--context-length", str(runtime["context_length"]),
        "--gpu", runtime["gpu"], "--parallel", str(runtime["parallel"]), "--yes")
    loaded = [m for m in json.loads(lms("ps", "--json")) if m.get("type") == "llm"]
    observed = {m.get("identifier"): (m.get("modelKey"), m.get("contextLength")) for m in loaded}
    expected = {model["identifier"]: (model["model_key"], runtime["context_length"])}
    if observed != expected:
        raise RuntimeError(f"loaded models differ from the study: expected {expected}, observed {observed}")
    return loaded


def keep_awake(enable: bool) -> None:
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | (0x00000001 if enable else 0))


def _fresh(directory: Path) -> Path:
    """The unit's directory, emptied: a run stopped half way is kept aside, never deleted."""
    if directory.exists():
        directory.rename(directory.with_name(f"{directory.name}.stopped-{int(time.time())}"))
    directory.mkdir(parents=True)
    return directory


def run_stage(study: dict[str, Any], stage: str, results: Path, *, models: list[str] | None = None,
              load: Callable[[dict[str, Any], dict[str, Any]], Any] | None = load_model,
              transport: Transport | None = None, scratch: bool = False) -> list[dict[str, Any]]:
    results.mkdir(parents=True, exist_ok=True)
    done = read_records(results)
    environment = {"stage": stage, "scratch": scratch, "git": git_state(study["frozen"]["paths"]),
                   "python": sys.version, "platform": platform.platform(), "study_sha256": file_digest(HERE / "study.json"),
                   "frozen": study["frozen"], "started": now(), "loaded": {}}
    made = []
    current_model = None
    for unit in units(study, stage, models):
        key = unit_key(unit)
        if key in done:
            continue
        if unit["model"] != SCRIPTED and unit["model"] != current_model:
            model = next(m for m in study["models"] if m["id"] == unit["model"])
            if load is not None:
                environment["loaded"][model["id"]] = load(study, model)
            current_model = unit["model"]
            (results / f"environment-{stage}.json").write_text(json.dumps(environment, indent=1, sort_keys=True),
                                                               encoding="utf-8")
        log(f"{key}: start")
        record = run_unit(unit, study, _fresh(results / unit["model"] / unit["name"]), transport=transport)
        record["scratch"] = scratch
        with open(results / "records.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        verdict = record.get("verification") or {}
        log(f"{key}: {record['status']}{' (' + record['cause'] + ')' if record.get('cause') else ''}, "
            f"violations {verdict.get('violations')}, complete {verdict.get('complete')}, {record['seconds']} s")
        made.append(record)
    environment["finished"] = now()
    (results / f"environment-{stage}.json").write_text(json.dumps(environment, indent=1, sort_keys=True), encoding="utf-8")
    return made


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--model", action="append", help="only these model ids ('scripted' for the scripted conditions)")
    parser.add_argument("--results", type=Path, help="write here instead of results/<stage>")
    parser.add_argument("--dry-run", action="store_true", help="list the units and stop")
    args = parser.parse_args(argv)

    study = load_study()
    check_frozen(study)
    results = (args.results or RESULTS / args.stage).resolve()
    todo = units(study, args.stage, args.model)
    if args.dry_run:
        for unit in todo:
            print(unit_key(unit))
        print(f"{len(todo)} unit(s)")
        return 0
    if args.stage == "full":
        if not registered():
            raise SystemExit("the study is not registered: PREREGISTRATION.md is still a draft")
        state = git_state(study["frozen"]["paths"])
        if state["dirty"]:
            raise SystemExit(f"frozen paths have uncommitted changes: {state['dirty_paths']}")
        verdict = qualified(study, RESULTS / "qualification")
        missing = [m for m in {u["model"] for u in todo} - {SCRIPTED} if not verdict.get(m)]
        if missing:
            raise SystemExit(f"not qualified: {sorted(missing)}")
    log(f"{args.stage}: {len(todo)} unit(s), results in {results}")
    keep_awake(True)
    try:
        run_stage(study, args.stage, results, models=args.model)
    finally:
        keep_awake(False)
    if args.stage == "qualification":
        log(f"qualified: {qualified(study, results)}")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUTF8", "1")
    raise SystemExit(main())
