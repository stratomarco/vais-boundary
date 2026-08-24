import json
from pathlib import Path

import pytest

from vais.benchmark_automation import (
    AutomationOptions,
    BenchmarkAutomationError,
    CommandResult,
    LMStudioRuntime,
    run_benchmark_all,
    validate_inventory,
    validate_stage_summary,
)
from vais.rc_benchmark import load_rc_manifest, render_checkpoint_report


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "benchmarks" / "rc" / "v0.12-model-panel.json"


def _inventory(manifest):
    return [
        {
            "type": "llm",
            "modelKey": model["local_model_key"],
            "format": "gguf",
            "paramsString": model["parameter_class"],
            "sizeBytes": 1000,
            "architecture": "test",
            "quantization": {"name": model["quantization"], "bits": 4},
            "maxContextLength": 32768,
        }
        for model in manifest["models"]
    ]


def _metrics(episodes, campaigns, model):
    return {
        "campaigns": campaigns,
        "episodes": episodes,
        "evaluable_episodes": episodes,
        "terminal_reward_one_count": 0,
        "terminal_reward_one_rate": 0.0,
        "target_failure_episodes": 0,
        "unique_target_generation_failures": 0,
        "attacker_generation_failures": 0,
        "pair_delta_unavailable_episodes": 0,
        "reasoning_mode_mismatch": False,
        "reasoning_tokens": 0,
        "reasoning_chars": 0,
        "reasoning_observed": model.get("reasoning_mode", "off") == "on",
        "reasoning_mode_label": model.get("reasoning_mode", "off"),
        "disable_thinking_request": str(
            model.get("reasoning_control", "adapter_request") == "adapter_request"
        ).lower(),
        "protected_workflow_utility_successes": episodes,
        "protected_workflow_utility_rate": 1.0,
        "attack_added_security_event_episodes": 0,
        "attack_added_security_event_rate": 0.0,
        "attack_objective_success_episodes": 0,
        "protected_violation_discovered": False,
    }


def _write_summary(path, manifest, model, stage):
    stage_config = manifest["stages"][stage]
    campaigns = len(stage_config["scenarios"]) if isinstance(stage_config["scenarios"], list) else 20
    episodes = campaigns * stage_config["episodes"]
    path.write_text(
        json.dumps(
            {
                "mode": "adaptive_verification",
                "framework_version": manifest["framework_version"],
                "campaigns": {},
                "by_target": {
                    f"lmstudio:{model['lmstudio_model']}": _metrics(episodes, campaigns, model)
                },
            }
        ),
        encoding="utf-8",
    )


class FakeRuntime:
    def __init__(self, manifest):
        self.manifest = manifest
        self.current = None
        self.started = 0
        self.unloaded = 0

    def ensure_server(self):
        self.started += 1

    def inventory(self):
        return _inventory(self.manifest)

    def server_catalog(self, **kwargs):
        catalog = []
        for item in _inventory(self.manifest):
            loaded_instances = []
            if self.current and self.current["model_key"] == item["modelKey"]:
                loaded_instances.append({
                    "id": self.current["identifier"],
                    "config": {
                        "context_length": self.current["context_length"],
                        "parallel": self.current["parallel"],
                    },
                })
            catalog.append({
                "type": item["type"], "key": item["modelKey"],
                "format": item["format"], "params_string": item["paramsString"],
                "size_bytes": item["sizeBytes"], "architecture": item["architecture"],
                "quantization": item["quantization"],
                "max_context_length": item["maxContextLength"],
                "loaded_instances": loaded_instances,
            })
        return catalog

    def unload_all(self):
        self.current = None
        self.unloaded += 1

    def load(self, **kwargs):
        self.current = kwargs

    def verify_loaded(self, **expected):
        assert self.current is not None
        assert self.current["model_key"] == expected["model_key"]
        assert self.current["identifier"] == expected["identifier"]
        assert self.current["context_length"] == expected["context_length"]
        assert self.current["parallel"] == expected["parallel"]
        return {
            "model_key": expected["model_key"],
            "identifier": expected["identifier"],
            "quantization": expected["quantization"],
            "context_length": expected["context_length"],
            "parallel": expected["parallel"],
        }


def test_inventory_requires_exact_model_key_quantization_and_context():
    manifest = load_rc_manifest(MANIFEST)
    inventory = _inventory(manifest)
    resolved = validate_inventory(manifest, inventory)
    assert len(resolved) == 15
    assert resolved["gemma-3-1b-it"]["model_key"] == "gemma-3-1b-it"

    inventory[0]["quantization"]["name"] = "Q8_0"
    with pytest.raises(BenchmarkAutomationError, match="quantization mismatch"):
        validate_inventory(manifest, inventory)


def test_inventory_rejects_missing_and_ambiguous_models():
    manifest = load_rc_manifest(MANIFEST)
    inventory = _inventory(manifest)
    with pytest.raises(BenchmarkAutomationError, match="observed 0"):
        validate_inventory(manifest, inventory[1:])
    with pytest.raises(BenchmarkAutomationError, match="observed 2"):
        validate_inventory(manifest, inventory + [dict(inventory[0])])


def test_runtime_uses_shell_free_exact_load_arguments_and_verifies_every_field():
    calls = []
    loaded = [{
        "type": "llm", "modelKey": "local-key", "identifier": "panel/model",
        "quantization": {"name": "Q4_K_M"}, "contextLength": 8192,
        "parallel": 1, "format": "gguf", "paramsString": "1B", "sizeBytes": 10,
        "architecture": "test",
    }]

    def runner(argv, capture):
        calls.append((tuple(argv), capture))
        return CommandResult(0, json.dumps(loaded) if argv[1:3] == ("ps", "--json") else "")

    runtime = LMStudioRuntime(command_runner=runner)
    runtime.load(model_key="local-key", identifier="panel/model", context_length=8192, gpu="max", parallel=1)
    snapshot = runtime.verify_loaded(
        model_key="local-key", identifier="panel/model", quantization="Q4_K_M",
        context_length=8192, parallel=1,
    )
    assert calls[0][0] == (
        "lms", "load", "local-key", "--identifier", "panel/model",
        "--context-length", "8192", "--gpu", "max", "--parallel", "1", "--yes",
    )
    assert calls[0][1] is False
    assert snapshot["identifier"] == "panel/model"


def test_loaded_model_verification_fails_closed_on_alias_swap():
    def runner(argv, capture):
        return CommandResult(0, json.dumps([{
            "type": "llm", "modelKey": "local-key", "identifier": "wrong/model",
            "quantization": {"name": "Q4_K_M"}, "contextLength": 8192, "parallel": 1,
        }]))

    with pytest.raises(BenchmarkAutomationError, match="configuration mismatch"):
        LMStudioRuntime(command_runner=runner).verify_loaded(
            model_key="local-key", identifier="panel/model", quantization="Q4_K_M",
            context_length=8192, parallel=1,
        )


def test_stage_validation_rejects_reasoning_failures_and_incomplete_pairs(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    model = manifest["models"][0]
    path = tmp_path / "summary.json"
    _write_summary(path, manifest, model, "preflight")
    raw = json.loads(path.read_text(encoding="utf-8"))
    metrics = next(iter(raw["by_target"].values()))
    metrics["reasoning_mode_mismatch"] = True
    metrics["reasoning_observed"] = True
    metrics["reasoning_tokens"] = 1
    metrics["pair_delta_unavailable_episodes"] = 1
    path.write_text(json.dumps(raw), encoding="utf-8")
    _, gates = validate_stage_summary(manifest, model, "preflight", path)
    assert gates == ["reasoning_mode_mismatch", "pair_delta_unavailable"]


def test_deepseek_uses_native_reasoning_profile_without_disable_request(tmp_path):
    from vais.benchmark_automation import _stage_argv

    manifest = load_rc_manifest(MANIFEST)
    deepseek = next(
        model for model in manifest["models"]
        if model["id"] == "deepseek-r1-distill-llama-8b"
    )
    options = AutomationOptions(
        output_dir=tmp_path / "results", report_dir=tmp_path / "report"
    )
    argv = _stage_argv(manifest, deepseek, "preflight", options)

    assert argv[argv.index("--target-reasoning-mode") + 1] == "on"
    assert "--target-disable-thinking" not in argv


def test_stage_validation_binds_reasoning_label_and_control_to_manifest(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    model = next(
        item for item in manifest["models"]
        if item["id"] == "deepseek-r1-distill-llama-8b"
    )
    path = tmp_path / "summary.json"
    _write_summary(path, manifest, model, "preflight")
    raw = json.loads(path.read_text(encoding="utf-8"))
    metrics = next(iter(raw["by_target"].values()))
    metrics["reasoning_mode_label"] = "off"
    metrics["disable_thinking_request"] = "true"
    path.write_text(json.dumps(raw), encoding="utf-8")

    _, gates = validate_stage_summary(manifest, model, "preflight", path)

    assert gates == ["reasoning_mode_label_mismatch", "reasoning_control_mismatch"]


def test_stage_validation_independently_derives_native_reasoning_conformance(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    model = next(
        item for item in manifest["models"]
        if item["id"] == "deepseek-r1-distill-llama-8b"
    )
    path = tmp_path / "summary.json"
    _write_summary(path, manifest, model, "preflight")
    raw = json.loads(path.read_text(encoding="utf-8"))
    metrics = next(iter(raw["by_target"].values()))
    metrics["reasoning_observed"] = False
    metrics["reasoning_tokens"] = 0
    metrics["reasoning_chars"] = 0
    metrics["reasoning_mode_mismatch"] = False
    path.write_text(json.dumps(raw), encoding="utf-8")

    _, gates = validate_stage_summary(manifest, model, "preflight", path)

    assert gates == [
        "reasoning_mode_mismatch",
        "reasoning_conformance_derivation_mismatch",
    ]


def test_automation_runs_four_stages_and_resumes_without_overwrite(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    model = manifest["models"][0]
    runtime = FakeRuntime(manifest)
    output = tmp_path / "results"
    options = AutomationOptions(
        output_dir=output,
        report_dir=output / "report",
        model_ids=(model["id"],),
    )
    calls = []

    def stage_runner(argv):
        argv = list(argv)
        calls.append(argv)
        stage = next(name for name in ("preflight", "qualification", "screening", "full")
                     if f"-{name}" in argv[argv.index("--summary") + 1])
        episodes_path = Path(argv[argv.index("--output") + 1])
        summary_path = Path(argv[argv.index("--summary") + 1])
        rlvr_path = Path(argv[argv.index("--rlvr-output") + 1])
        episodes_path.write_text("{}\n", encoding="utf-8")
        rlvr_path.write_text("{}\n", encoding="utf-8")
        _write_summary(summary_path, manifest, model, stage)
        return 0

    state, code = run_benchmark_all(
        manifest, options, runtime=runtime, stage_runner=stage_runner
    )
    assert code == 0
    assert state["models"][model["id"]]["status"] == "completed"
    assert len(calls) == 4
    assert all(
        call[call.index("--target-truncation-retry-tokens") + 1] == "4096"
        for call in calls
    )
    assert (output / "report" / "benchmark-report.html").is_file()
    assert (output / "benchmark-state.json").is_file()

    def must_not_run(argv):
        raise AssertionError(f"resume attempted to rerun: {argv}")

    resumed, resumed_code = run_benchmark_all(
        manifest, options, runtime=runtime, stage_runner=must_not_run
    )
    assert resumed_code == 0
    assert resumed["models"][model["id"]]["status"] == "completed"


def test_dry_run_validates_all_models_without_loading(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    runtime = FakeRuntime(manifest)
    options = AutomationOptions(
        output_dir=tmp_path / "results",
        report_dir=tmp_path / "report",
        dry_run=True,
    )
    state, code = run_benchmark_all(manifest, options, runtime=runtime)
    assert code == 0
    assert state["status"] == "validated"
    assert runtime.current is None
    assert len(state["inventory"]) == 15


def test_model_gate_failure_stops_that_model_but_continues_panel(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    first, second = manifest["models"][0], next(
        model for model in manifest["models"] if model["id"] == "llama-3.2-1b-instruct"
    )
    runtime = FakeRuntime(manifest)
    options = AutomationOptions(
        output_dir=tmp_path / "results",
        report_dir=tmp_path / "report",
        model_ids=(first["id"], second["id"]),
    )

    def stage_runner(argv):
        argv = list(argv)
        target = argv[argv.index("--target-model") + 1]
        model = first if target == first["lmstudio_model"] else second
        stage = next(name for name in ("preflight", "qualification", "screening", "full")
                     if f"-{name}" in argv[argv.index("--summary") + 1])
        episodes_path = Path(argv[argv.index("--output") + 1])
        summary_path = Path(argv[argv.index("--summary") + 1])
        rlvr_path = Path(argv[argv.index("--rlvr-output") + 1])
        episodes_path.write_text("{}\n", encoding="utf-8")
        rlvr_path.write_text("{}\n", encoding="utf-8")
        _write_summary(summary_path, manifest, model, stage)
        if model is first:
            raw = json.loads(summary_path.read_text(encoding="utf-8"))
            next(iter(raw["by_target"].values()))["reasoning_mode_mismatch"] = True
            summary_path.write_text(json.dumps(raw), encoding="utf-8")
            return 5
        return 0

    state, code = run_benchmark_all(
        manifest, options, runtime=runtime, stage_runner=stage_runner
    )
    assert code == 5
    assert state["status"] == "complete_with_failures"
    assert state["models"][first["id"]]["status"] == "gate_failed"
    assert state["models"][first["id"]]["failed_stage"] == "preflight"
    assert state["models"][second["id"]]["status"] == "completed"
    report = (options.report_dir / "benchmark-report.html").read_text(encoding="utf-8")
    assert "GATE_FAILED" in report
    assert "COMPLETED" in report

    resumed, resumed_code = run_benchmark_all(
        manifest,
        options,
        runtime=runtime,
        stage_runner=lambda argv: (_ for _ in ()).throw(AssertionError(argv)),
    )
    assert resumed_code == 5
    assert resumed["models"][first["id"]]["status"] == "gate_failed"


def test_report_retains_gate_triggering_violation_from_earlier_stage(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    first, second = manifest["models"][0], manifest["models"][1]
    runtime = FakeRuntime(manifest)
    output = tmp_path / "results"
    options = AutomationOptions(
        output_dir=output,
        report_dir=output / "report",
        model_ids=(first["id"], second["id"]),
    )

    def stage_runner(argv):
        argv = list(argv)
        target = argv[argv.index("--target-model") + 1]
        model = first if target == first["lmstudio_model"] else second
        stage = next(
            name
            for name in ("preflight", "qualification", "screening", "full")
            if f"-{name}" in argv[argv.index("--summary") + 1]
        )
        Path(argv[argv.index("--output") + 1]).write_text("{}\n", encoding="utf-8")
        Path(argv[argv.index("--rlvr-output") + 1]).write_text("{}\n", encoding="utf-8")
        summary_path = Path(argv[argv.index("--summary") + 1])
        _write_summary(summary_path, manifest, model, stage)
        if model is first and stage == "screening":
            raw = json.loads(summary_path.read_text(encoding="utf-8"))
            metrics = next(iter(raw["by_target"].values()))
            metrics["terminal_reward_one_count"] = 1
            metrics["terminal_reward_one_rate"] = 1 / metrics["evaluable_episodes"]
            metrics["protected_violation_discovered"] = True
            summary_path.write_text(json.dumps(raw), encoding="utf-8")
            return 2
        return 0

    state, code = run_benchmark_all(
        manifest, options, runtime=runtime, stage_runner=stage_runner
    )

    assert code == 2
    assert state["status"] == "complete_with_failures"
    aggregate = json.loads(
        (options.report_dir / "rc-aggregate.json").read_text(encoding="utf-8")
    )
    assert aggregate["models_completed"] == 1
    assert aggregate["models_gate_failed"] == 1
    assert aggregate["protected_violations"] == 1
    assert aggregate["execution_evidence"]["evaluable_episodes"] == 374
    failed = next(row for row in aggregate["models"] if row["id"] == first["id"])
    assert failed["status"] == "gate_failed"
    assert failed["automation"]["evidence_stage"] == "screening"
    assert failed["metrics"]["terminal_reward_one_count"] == 1
    report = (options.report_dir / "benchmark-report.html").read_text(encoding="utf-8")
    assert "Complete with gate failures" in report
    assert "Protected-effect alert" in report
    assert "1/60 (1.7%)" in report
    assert "In progress:" not in report


def test_checkpoint_hash_tampering_is_detected_before_resume(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    model = manifest["models"][0]
    runtime = FakeRuntime(manifest)
    options = AutomationOptions(
        output_dir=tmp_path / "results",
        report_dir=tmp_path / "report",
        model_ids=(model["id"],),
    )

    def stage_runner(argv):
        argv = list(argv)
        stage = next(name for name in ("preflight", "qualification", "screening", "full")
                     if f"-{name}" in argv[argv.index("--summary") + 1])
        Path(argv[argv.index("--output") + 1]).write_text("{}\n", encoding="utf-8")
        Path(argv[argv.index("--rlvr-output") + 1]).write_text("{}\n", encoding="utf-8")
        _write_summary(Path(argv[argv.index("--summary") + 1]), manifest, model, stage)
        return 0

    state, _ = run_benchmark_all(manifest, options, runtime=runtime, stage_runner=stage_runner)
    summary = Path(state["models"][model["id"]]["stages"]["full"]["artifacts"]["summary"]["path"])
    summary.write_text(summary.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(BenchmarkAutomationError, match="artifacts changed"):
        run_benchmark_all(manifest, options, runtime=runtime, stage_runner=stage_runner)


def test_offline_report_verifies_checkpoint_artifacts_before_rendering(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    model = manifest["models"][0]
    runtime = FakeRuntime(manifest)
    options = AutomationOptions(
        output_dir=tmp_path / "results",
        report_dir=tmp_path / "live-report",
        model_ids=(model["id"],),
    )

    def stage_runner(argv):
        argv = list(argv)
        stage = next(name for name in ("preflight", "qualification", "screening", "full")
                     if f"-{name}" in argv[argv.index("--summary") + 1])
        Path(argv[argv.index("--output") + 1]).write_text("{}\n", encoding="utf-8")
        Path(argv[argv.index("--rlvr-output") + 1]).write_text("{}\n", encoding="utf-8")
        _write_summary(Path(argv[argv.index("--summary") + 1]), manifest, model, stage)
        return 0

    state, code = run_benchmark_all(
        manifest, options, runtime=runtime, stage_runner=stage_runner
    )
    assert code == 0
    rendered = render_checkpoint_report(
        manifest,
        options.output_dir / "benchmark-state.json",
        tmp_path / "offline-report",
        artifact_root=options.output_dir,
    )
    assert rendered["input_integrity"]["artifacts_verified"] == 12
    assert rendered["evidence_version"] == "0.12.0rc9"
    assert (tmp_path / "offline-report" / "report-evidence-manifest.json").is_file()

    summary = Path(state["models"][model["id"]]["stages"]["full"]["artifacts"]["summary"]["path"])
    summary.write_text(summary.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="(?:size|hash) mismatch"):
        render_checkpoint_report(
            manifest,
            options.output_dir / "benchmark-state.json",
            tmp_path / "tampered-report",
            artifact_root=options.output_dir,
        )


def test_automation_refuses_remote_lifecycle_endpoint(tmp_path):
    with pytest.raises(ValueError, match="restricted to a local"):
        AutomationOptions(
            output_dir=tmp_path,
            report_dir=tmp_path / "report",
            target_base_url="https://remote.example/v1",
        )


def test_resume_recovers_complete_stage_written_immediately_before_interrupt(tmp_path):
    manifest = load_rc_manifest(MANIFEST)
    model = manifest["models"][0]
    runtime = FakeRuntime(manifest)
    options = AutomationOptions(
        output_dir=tmp_path / "results",
        report_dir=tmp_path / "report",
        model_ids=(model["id"],),
    )

    def interrupted_runner(argv):
        argv = list(argv)
        Path(argv[argv.index("--output") + 1]).write_text("{}\n", encoding="utf-8")
        Path(argv[argv.index("--rlvr-output") + 1]).write_text("{}\n", encoding="utf-8")
        _write_summary(
            Path(argv[argv.index("--summary") + 1]), manifest, model, "preflight"
        )
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_benchmark_all(
            manifest, options, runtime=runtime, stage_runner=interrupted_runner
        )

    resumed_calls = []

    def resumed_runner(argv):
        argv = list(argv)
        resumed_calls.append(argv)
        stage = next(name for name in ("qualification", "screening", "full")
                     if f"-{name}" in argv[argv.index("--summary") + 1])
        Path(argv[argv.index("--output") + 1]).write_text("{}\n", encoding="utf-8")
        Path(argv[argv.index("--rlvr-output") + 1]).write_text("{}\n", encoding="utf-8")
        _write_summary(Path(argv[argv.index("--summary") + 1]), manifest, model, stage)
        return 0

    state, code = run_benchmark_all(
        manifest, options, runtime=runtime, stage_runner=resumed_runner
    )
    assert code == 0
    assert len(resumed_calls) == 3
    assert state["models"][model["id"]]["stages"]["preflight"][
        "recovered_after_interruption"
    ] is True
