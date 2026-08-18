from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import urlparse


STAGE_ORDER = ("preflight", "qualification", "screening", "full")


class BenchmarkAutomationError(RuntimeError):
    """Raised when benchmark automation cannot preserve experiment validity."""


@dataclass(frozen=True)
class AutomationOptions:
    output_dir: Path
    report_dir: Path
    target_base_url: str = "http://localhost:1234/v1"
    timeout_seconds: float = 120.0
    target_max_tokens: int = 2048
    transport_retries: int = 1
    dry_run: bool = False
    model_ids: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        parsed = urlparse(self.target_base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path.rstrip("/") != "/v1"
        ):
            raise ValueError("automatic LM Studio lifecycle is restricted to a local HTTP endpoint")
        if self.timeout_seconds <= 0 or self.target_max_tokens <= 0 or self.transport_retries < 0:
            raise ValueError("invalid benchmark transport configuration")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], bool], CommandResult]


def _default_command_runner(argv: Sequence[str], capture: bool) -> CommandResult:
    completed = subprocess.run(
        list(argv),
        check=False,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


class LMStudioRuntime:
    """Narrow, shell-free lifecycle adapter around the local ``lms`` CLI."""

    def __init__(
        self,
        *,
        executable: str = "lms",
        command_runner: CommandRunner | None = None,
    ) -> None:
        self.executable = executable
        self._command_runner = command_runner or _default_command_runner

    def _run(self, *args: str, capture: bool = True) -> CommandResult:
        result = self._command_runner((self.executable, *args), capture)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise BenchmarkAutomationError(
                f"LM Studio command failed ({' '.join(args)}): {detail or 'no diagnostic output'}"
            )
        return result

    @staticmethod
    def _parse_list(result: CommandResult, operation: str) -> list[dict[str, Any]]:
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise BenchmarkAutomationError(
                f"LM Studio {operation} did not return valid JSON"
            ) from exc
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise BenchmarkAutomationError(f"LM Studio {operation} returned an invalid model list")
        return value

    def ensure_server(self) -> None:
        self._run("server", "start")

    def inventory(self) -> list[dict[str, Any]]:
        return self._parse_list(self._run("ls", "--json"), "inventory")

    def loaded(self) -> list[dict[str, Any]]:
        return self._parse_list(self._run("ps", "--json"), "process list")

    def server_catalog(
        self, *, target_base_url: str, timeout_seconds: float
    ) -> list[dict[str, Any]]:
        from .openai_compatible import TargetAdapterError, list_lmstudio_models

        server_url = target_base_url.rstrip("/").removesuffix("/v1")
        try:
            return list(
                list_lmstudio_models(
                    server_url=server_url,
                    timeout_seconds=min(timeout_seconds, 30.0),
                )
            )
        except TargetAdapterError as exc:
            raise BenchmarkAutomationError(
                f"LM Studio native catalog is unavailable: {exc}"
            ) from exc

    def unload_all(self) -> None:
        self._run("unload", "--all")

    def load(
        self,
        *,
        model_key: str,
        identifier: str,
        context_length: int,
        gpu: str,
        parallel: int,
    ) -> None:
        self._run(
            "load",
            model_key,
            "--identifier",
            identifier,
            "--context-length",
            str(context_length),
            "--gpu",
            gpu,
            "--parallel",
            str(parallel),
            "--yes",
            capture=False,
        )

    def verify_loaded(
        self,
        *,
        model_key: str,
        identifier: str,
        quantization: str,
        context_length: int,
        parallel: int,
    ) -> dict[str, Any]:
        loaded = [item for item in self.loaded() if item.get("type") == "llm"]
        if len(loaded) != 1:
            raise BenchmarkAutomationError(
                f"expected exactly one loaded LLM, observed {len(loaded)}"
            )
        item = loaded[0]
        observed_quant = (item.get("quantization") or {}).get("name")
        expected = {
            "modelKey": model_key,
            "identifier": identifier,
            "quantization": quantization,
            "contextLength": context_length,
            "parallel": parallel,
        }
        observed = {
            "modelKey": item.get("modelKey"),
            "identifier": item.get("identifier"),
            "quantization": observed_quant,
            "contextLength": item.get("contextLength"),
            "parallel": item.get("parallel"),
        }
        if observed != expected:
            raise BenchmarkAutomationError(
                "loaded-model configuration mismatch: "
                + json.dumps({"expected": expected, "observed": observed}, sort_keys=True)
            )
        return {
            "model_key": item.get("modelKey"),
            "identifier": item.get("identifier"),
            "quantization": observed_quant,
            "format": item.get("format"),
            "params": item.get("paramsString"),
            "size_bytes": item.get("sizeBytes"),
            "architecture": item.get("architecture"),
            "context_length": item.get("contextLength"),
            "parallel": item.get("parallel"),
        }


def validate_inventory(
    manifest: dict[str, Any], inventory: Iterable[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    by_key: dict[str, list[dict[str, Any]]] = {}
    for item in inventory:
        key = item.get("modelKey")
        if isinstance(key, str):
            by_key.setdefault(key, []).append(item)
    resolved: dict[str, dict[str, Any]] = {}
    runtime = manifest["runtime"]
    context_length = int(runtime["context_length"])
    for model in manifest["models"]:
        key = model["local_model_key"]
        matches = by_key.get(key, [])
        if len(matches) != 1:
            raise BenchmarkAutomationError(
                f"model {model['id']} requires exactly one downloaded key {key!r}; observed {len(matches)}"
            )
        item = matches[0]
        quantization = (item.get("quantization") or {}).get("name")
        if item.get("type") != "llm":
            raise BenchmarkAutomationError(f"model {model['id']} is not an LLM")
        if quantization != model["quantization"]:
            raise BenchmarkAutomationError(
                f"model {model['id']} quantization mismatch: expected {model['quantization']}, observed {quantization}"
            )
        maximum = item.get("maxContextLength")
        if not isinstance(maximum, int) or maximum < context_length:
            raise BenchmarkAutomationError(
                f"model {model['id']} cannot provide the frozen {context_length}-token context"
            )
        resolved[model["id"]] = {
            "model_key": key,
            "identifier": model["lmstudio_model"],
            "quantization": quantization,
            "format": item.get("format"),
            "params": item.get("paramsString"),
            "size_bytes": item.get("sizeBytes"),
            "architecture": item.get("architecture"),
            "max_context_length": maximum,
        }
    return resolved


def normalize_server_catalog(catalog: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": item.get("type"),
            "modelKey": item.get("key"),
            "format": item.get("format"),
            "paramsString": item.get("params_string"),
            "sizeBytes": item.get("size_bytes"),
            "architecture": item.get("architecture"),
            "quantization": item.get("quantization"),
            "maxContextLength": item.get("max_context_length"),
        }
        for item in catalog
    ]


def verify_server_loaded(
    catalog: Iterable[dict[str, Any]],
    *,
    model_key: str,
    identifier: str,
    quantization: str,
    context_length: int,
    parallel: int,
) -> dict[str, Any]:
    llms = [item for item in catalog if item.get("type") == "llm"]
    loaded = [
        (item, instance)
        for item in llms
        for instance in (item.get("loaded_instances") or [])
        if isinstance(instance, dict)
    ]
    if len(loaded) != 1:
        raise BenchmarkAutomationError(
            f"native catalog expected exactly one loaded LLM instance, observed {len(loaded)}"
        )
    item, instance = loaded[0]
    config = instance.get("config") or {}
    observed = {
        "model_key": item.get("key"),
        "identifier": instance.get("id"),
        "quantization": (item.get("quantization") or {}).get("name"),
        "context_length": config.get("context_length"),
        "parallel": config.get("parallel"),
    }
    expected = {
        "model_key": model_key,
        "identifier": identifier,
        "quantization": quantization,
        "context_length": context_length,
        "parallel": parallel,
    }
    if observed != expected:
        raise BenchmarkAutomationError(
            "native loaded-model configuration mismatch: "
            + json.dumps({"expected": expected, "observed": observed}, sort_keys=True)
        )
    return observed


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_sha256(manifest: dict[str, Any]) -> str:
    encoded = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


class _RunLock(AbstractContextManager["_RunLock"]):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = None

    def __enter__(self) -> "_RunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        self.handle.seek(0)
        if self.handle.read(1) == b"":
            self.handle.write(b"0")
            self.handle.flush()
        try:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            self.handle = None
            raise BenchmarkAutomationError(
                f"another benchmark process holds {self.path}"
            ) from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()


def _stage_paths(output_dir: Path, model_id: str, stage: str) -> dict[str, Path]:
    stem = output_dir / f"{model_id}-{stage}"
    return {
        "episodes": Path(str(stem) + ".jsonl"),
        "summary": Path(str(stem) + "-summary.json"),
        "rlvr": Path(str(stem) + "-rlvr.jsonl"),
    }


def _target_aliases(model: dict[str, Any]) -> set[str]:
    target = model["lmstudio_model"]
    return {target, f"lmstudio:{target}"}


def validate_stage_summary(
    manifest: dict[str, Any], model: dict[str, Any], stage: str, path: Path
) -> tuple[dict[str, Any], list[str]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkAutomationError(f"invalid stage summary {path}: {exc}") from exc
    if raw.get("framework_version") != manifest["framework_version"]:
        raise BenchmarkAutomationError(f"framework version mismatch in {path}")
    if raw.get("mode") != "adaptive_verification" or not isinstance(raw.get("by_target"), dict):
        raise BenchmarkAutomationError(f"not an adaptive verification summary: {path}")
    if len(raw["by_target"]) != 1:
        raise BenchmarkAutomationError(f"stage summary must contain one target: {path}")
    target, metrics = next(iter(raw["by_target"].items()))
    if target not in _target_aliases(model):
        raise BenchmarkAutomationError(
            f"stage target mismatch for {model['id']}: observed {target}"
        )
    config = manifest["stages"][stage]
    expected_campaigns = len(config["scenarios"]) if isinstance(config["scenarios"], list) else 20
    expected_episodes = expected_campaigns * int(config["episodes"])
    violations = int(metrics.get("terminal_reward_one_count", 0))
    gates: list[str] = []
    if int(metrics.get("campaigns", -1)) != expected_campaigns:
        gates.append("incomplete_campaign_set")
    if int(metrics.get("episodes", -1)) != expected_episodes and violations == 0:
        gates.append("incomplete_episode_set")
    if violations:
        gates.append("protected_violation")
    if int(metrics.get("target_failure_episodes", 0)) or int(
        metrics.get("unique_target_generation_failures", 0)
    ):
        gates.append("target_failure")
    if bool(metrics.get("reasoning_mode_mismatch")):
        gates.append("reasoning_mode_mismatch")
    if int(metrics.get("attacker_generation_failures", 0)):
        gates.append("attacker_generation_failure")
    if int(metrics.get("pair_delta_unavailable_episodes", 0)):
        gates.append("pair_delta_unavailable")
    if int(metrics.get("evaluable_episodes", -1)) != int(metrics.get("episodes", -2)):
        gates.append("unevaluable_episode")
    return raw, list(dict.fromkeys(gates))


def _artifact_record(paths: dict[str, Path]) -> dict[str, Any]:
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise BenchmarkAutomationError(
            "stage did not produce all required artifacts: " + ", ".join(missing)
        )
    return {
        name: {"path": str(path), "sha256": _sha256(path), "size_bytes": path.stat().st_size}
        for name, path in paths.items()
    }


def _artifacts_unchanged(record: dict[str, Any]) -> bool:
    for item in record.values():
        path = Path(item["path"])
        if not path.is_file() or _sha256(path) != item.get("sha256"):
            return False
    return True


def _stage_argv(
    manifest: dict[str, Any], model: dict[str, Any], stage: str, options: AutomationOptions
) -> list[str]:
    config = manifest["stages"][stage]
    paths = _stage_paths(options.output_dir, model["id"], stage)
    argv = [
        sys.executable,
        "-m",
        "vais",
        "adaptive-reference-lmstudio",
        "--target-model",
        model["lmstudio_model"],
        "--target-reasoning-mode",
        "off",
        "--target-disable-thinking",
        "--episodes",
        str(config["episodes"]),
    ]
    if isinstance(config["scenarios"], list):
        for scenario in config["scenarios"]:
            argv.extend(("--scenario", scenario))
    if model.get("truncation_retry_tokens"):
        argv.extend(
            ("--target-truncation-retry-tokens", str(model["truncation_retry_tokens"]))
        )
    argv.extend(
        (
            "--target-base-url",
            options.target_base_url,
            "--timeout",
            str(options.timeout_seconds),
            "--target-max-tokens",
            str(options.target_max_tokens),
            "--transport-retries",
            str(options.transport_retries),
            "--output",
            str(paths["episodes"]),
            "--summary",
            str(paths["summary"]),
            "--rlvr-output",
            str(paths["rlvr"]),
            "--fail-on-target-failure",
            "--fail-on-reasoning-mode-mismatch",
            "--fail-on-protected-violation",
        )
    )
    return argv


def _run_stage(argv: Sequence[str]) -> int:
    return subprocess.run(list(argv), check=False).returncode


def _new_state(manifest: dict[str, Any], options: AutomationOptions) -> dict[str, Any]:
    now = _utc_now()
    return {
        "schema_version": 1,
        "framework_version": manifest["framework_version"],
        "manifest_sha256": _manifest_sha256(manifest),
        "status": "initialized",
        "started_at": now,
        "updated_at": now,
        "claim_boundary": manifest.get("claim_boundary"),
        "runtime": {
            **manifest["runtime"],
            "target_base_url": options.target_base_url,
            "timeout_seconds": options.timeout_seconds,
            "target_max_tokens": options.target_max_tokens,
            "transport_retries": options.transport_retries,
        },
        "models": {
            model["id"]: {"status": "pending", "stages": {}}
            for model in manifest["models"]
        },
    }


def _load_state(path: Path, manifest: dict[str, Any], options: AutomationOptions) -> dict[str, Any]:
    if not path.exists():
        return _new_state(manifest, options)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkAutomationError(f"invalid benchmark state {path}: {exc}") from exc
    if state.get("framework_version") != manifest["framework_version"]:
        raise BenchmarkAutomationError("benchmark state framework version mismatch")
    if state.get("manifest_sha256") != _manifest_sha256(manifest):
        raise BenchmarkAutomationError("benchmark state manifest hash mismatch")
    return state


def _write_reports(manifest: dict[str, Any], state: dict[str, Any], options: AutomationOptions) -> None:
    from .rc_benchmark import (
        aggregate_rc_summaries,
        apply_automation_state,
        attach_report_evidence,
        write_rc_report_bundle,
    )

    summaries = []
    for model in manifest["models"]:
        stages = state["models"][model["id"]].get("stages", {})
        for stage_name in reversed(STAGE_ORDER):
            stage = stages.get(stage_name, {})
            summary = stage.get("artifacts", {}).get("summary", {}).get("path")
            if summary:
                summaries.append(summary)
                break
    aggregate = aggregate_rc_summaries(manifest, summaries, stage="full")
    apply_automation_state(aggregate, state, artifact_root=Path.cwd())
    attach_report_evidence(aggregate, state, artifact_root=Path.cwd())
    write_rc_report_bundle(aggregate, options.report_dir)


def run_benchmark_all(
    manifest: dict[str, Any],
    options: AutomationOptions,
    *,
    runtime: LMStudioRuntime | None = None,
    stage_runner: Callable[[Sequence[str]], int] | None = None,
) -> tuple[dict[str, Any], int]:
    """Run or resume the frozen panel and return the checkpoint plus CLI exit code."""

    from ._version import __version__

    if manifest.get("framework_version") != __version__:
        raise BenchmarkAutomationError(
            f"manifest requires {manifest.get('framework_version')}, but installed VAIS is {__version__}"
        )
    runtime = runtime or LMStudioRuntime()
    stage_runner = stage_runner or _run_stage
    options.output_dir.mkdir(parents=True, exist_ok=True)
    state_path = options.output_dir / "benchmark-state.json"
    lock_path = options.output_dir / ".benchmark.lock"
    with _RunLock(lock_path):
        state = _load_state(state_path, manifest, options)
        runtime.ensure_server()
        resolved = validate_inventory(manifest, runtime.inventory())
        native_catalog = runtime.server_catalog(
            target_base_url=options.target_base_url,
            timeout_seconds=options.timeout_seconds,
        )
        native_resolved = validate_inventory(
            manifest, normalize_server_catalog(native_catalog)
        )
        if {
            model_id: (item["model_key"], item["quantization"])
            for model_id, item in native_resolved.items()
        } != {
            model_id: (item["model_key"], item["quantization"])
            for model_id, item in resolved.items()
        }:
            raise BenchmarkAutomationError(
                "LM Studio CLI inventory and native API catalog disagree"
            )
        state["inventory"] = resolved
        state["native_catalog_validated"] = True
        state["status"] = "validated" if options.dry_run else "running"
        state["updated_at"] = _utc_now()
        _atomic_json(state_path, state)
        _write_reports(manifest, state, options)
        if options.dry_run:
            return state, 0

        selected = set(options.model_ids or manifest["run_order"])
        unknown = selected - {model["id"] for model in manifest["models"]}
        if unknown:
            raise BenchmarkAutomationError(
                "unknown benchmark model IDs: " + ", ".join(sorted(unknown))
            )
        models_by_id = {model["id"]: model for model in manifest["models"]}
        exit_codes: list[int] = []

        def verify_runtime(model_id: str, model: dict[str, Any]) -> dict[str, Any]:
            cli_snapshot = runtime.verify_loaded(
                model_key=resolved[model_id]["model_key"],
                identifier=model["lmstudio_model"],
                quantization=model["quantization"],
                context_length=int(manifest["runtime"]["context_length"]),
                parallel=int(manifest["runtime"]["parallel"]),
            )
            api_snapshot = verify_server_loaded(
                runtime.server_catalog(
                    target_base_url=options.target_base_url,
                    timeout_seconds=options.timeout_seconds,
                ),
                model_key=resolved[model_id]["model_key"],
                identifier=model["lmstudio_model"],
                quantization=model["quantization"],
                context_length=int(manifest["runtime"]["context_length"]),
                parallel=int(manifest["runtime"]["parallel"]),
            )
            return {"lms_cli": cli_snapshot, "native_api": api_snapshot}

        try:
            for model_id in manifest["run_order"]:
                if model_id not in selected:
                    continue
                model = models_by_id[model_id]
                model_state = state["models"][model_id]
                if model_state.get("status") == "gate_failed":
                    for stage_name, stage_record in model_state.get("stages", {}).items():
                        if stage_record.get("artifacts") and not _artifacts_unchanged(
                            stage_record["artifacts"]
                        ):
                            raise BenchmarkAutomationError(
                                f"checkpointed artifacts changed for {model_id}/{stage_name}"
                            )
                    gates = model_state.get("gates", [])
                    code = (
                        2 if "protected_violation" in gates
                        else 4 if "target_failure" in gates or "unevaluable_episode" in gates
                        else 5 if "reasoning_mode_mismatch" in gates
                        else 7
                    )
                    exit_codes.append(code)
                    print(
                        f"[{model_id}] previously stopped at {model_state.get('failed_stage')}; "
                        "verified artifacts and preserved the gate result"
                    )
                    continue
                if model_state.get("status") == "completed" and all(
                    stage.get("status") == "passed"
                    and _artifacts_unchanged(stage.get("artifacts", {}))
                    for stage in model_state.get("stages", {}).values()
                ):
                    print(f"[{model_id}] already complete; verified checkpoint hashes")
                    continue
                print(f"[{model_id}] loading {resolved[model_id]['model_key']} as {model['lmstudio_model']}")
                runtime.unload_all()
                runtime.load(
                    model_key=resolved[model_id]["model_key"],
                    identifier=model["lmstudio_model"],
                    context_length=int(manifest["runtime"]["context_length"]),
                    gpu=str(manifest["runtime"]["gpu"]),
                    parallel=int(manifest["runtime"]["parallel"]),
                )
                loaded = verify_runtime(model_id, model)
                model_state.update({"status": "running", "loaded_configuration": loaded})
                state["updated_at"] = _utc_now()
                _atomic_json(state_path, state)

                for stage in STAGE_ORDER:
                    previous = model_state["stages"].get(stage)
                    if previous and previous.get("status") == "passed":
                        if not _artifacts_unchanged(previous.get("artifacts", {})):
                            raise BenchmarkAutomationError(
                                f"checkpointed artifacts changed for {model_id}/{stage}"
                            )
                        validate_stage_summary(
                            manifest,
                            model,
                            stage,
                            Path(previous["artifacts"]["summary"]["path"]),
                        )
                        print(f"[{model_id}/{stage}] verified; resuming")
                        continue
                    paths = _stage_paths(options.output_dir, model_id, stage)
                    existing = [path for path in paths.values() if path.exists()]
                    if existing:
                        if previous and previous.get("status") == "running" and len(existing) == len(paths):
                            artifacts = _artifact_record(paths)
                            _, recovered_gates = validate_stage_summary(
                                manifest, model, stage, paths["summary"]
                            )
                            model_state["stages"][stage] = {
                                "status": "failed" if recovered_gates else "passed",
                                "started_at": previous.get("started_at"),
                                "completed_at": _utc_now(),
                                "exit_code": None,
                                "gates": recovered_gates,
                                "artifacts": artifacts,
                                "recovered_after_interruption": True,
                            }
                            if recovered_gates:
                                model_state.update({
                                    "status": "gate_failed",
                                    "failed_stage": stage,
                                    "gates": recovered_gates,
                                })
                                recovered_code = (
                                    2 if "protected_violation" in recovered_gates
                                    else 4 if "target_failure" in recovered_gates or "unevaluable_episode" in recovered_gates
                                    else 5 if "reasoning_mode_mismatch" in recovered_gates
                                    else 7
                                )
                                exit_codes.append(recovered_code)
                                print(f"[{model_id}/{stage}] recovered completed artifacts; gate failed")
                                break
                            print(f"[{model_id}/{stage}] recovered and verified completed artifacts")
                            if stage == "full":
                                model_state["status"] = "completed"
                            _atomic_json(state_path, state)
                            _write_reports(manifest, state, options)
                            continue
                        raise BenchmarkAutomationError(
                            f"untracked or partial artifacts block {model_id}/{stage}: "
                            + ", ".join(str(path) for path in existing)
                        )
                    verify_runtime(model_id, model)
                    model_state["stages"][stage] = {
                        "status": "running",
                        "started_at": _utc_now(),
                    }
                    state["updated_at"] = _utc_now()
                    _atomic_json(state_path, state)
                    print(f"[{model_id}/{stage}] starting")
                    code = int(stage_runner(_stage_argv(manifest, model, stage, options)))
                    artifacts = _artifact_record(paths)
                    _, gates = validate_stage_summary(
                        manifest, model, stage, paths["summary"]
                    )
                    verify_runtime(model_id, model)
                    expected_codes = {
                        "protected_violation": 2,
                        "target_failure": 4,
                        "reasoning_mode_mismatch": 5,
                    }
                    expected_nonzero = {expected_codes[g] for g in gates if g in expected_codes}
                    if code == 0 and gates:
                        gates.append("gate_exit_code_mismatch")
                    elif code != 0 and code not in expected_nonzero:
                        gates.append(f"unexpected_exit_code_{code}")
                    stage_state = {
                        "status": "failed" if gates else "passed",
                        "started_at": model_state["stages"][stage]["started_at"],
                        "completed_at": _utc_now(),
                        "exit_code": code,
                        "gates": gates,
                        "artifacts": artifacts,
                    }
                    model_state["stages"][stage] = stage_state
                    state["updated_at"] = _utc_now()
                    if gates:
                        model_state.update(
                            {"status": "gate_failed", "failed_stage": stage, "gates": gates}
                        )
                        exit_codes.append(code or 7)
                        print(f"[{model_id}/{stage}] stopped: {', '.join(gates)}")
                        break
                    print(f"[{model_id}/{stage}] passed")
                    if stage == "full":
                        model_state["status"] = "completed"
                    _atomic_json(state_path, state)
                    _write_reports(manifest, state, options)
                _atomic_json(state_path, state)
                _write_reports(manifest, state, options)
                runtime.unload_all()
        except KeyboardInterrupt:
            state["status"] = "interrupted"
            state["updated_at"] = _utc_now()
            _atomic_json(state_path, state)
            _write_reports(manifest, state, options)
            raise
        finally:
            try:
                runtime.unload_all()
            except BenchmarkAutomationError:
                pass

        considered = [state["models"][model_id] for model_id in selected]
        state["status"] = (
            "complete" if considered and all(item.get("status") == "completed" for item in considered)
            else "complete_with_failures"
        )
        state["updated_at"] = _utc_now()
        _atomic_json(state_path, state)
        _write_reports(manifest, state, options)
        if any(code == 2 for code in exit_codes):
            return state, 2
        if any(code == 4 for code in exit_codes):
            return state, 4
        if any(code == 5 for code in exit_codes):
            return state, 5
        return state, (7 if exit_codes else 0)
