from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path

from .invariants import load_invariants
from .policy import load_policy


def _add_common_benchmark_args(parser: argparse.ArgumentParser, *, default_output: str) -> None:
    parser.add_argument("--output", default=default_output, help="JSONL episode output path")
    parser.add_argument("--summary", default=None, help="optional JSON summary output path")
    parser.add_argument(
        "--attack-corpus",
        default=None,
        help=("optional JSONL attack corpus; use 'bundled:v0.6' for the packaged direct static corpus or 'bundled:v0.8-mcp' "
              "for the MCP-delivered 125-case corpus; otherwise use each scenario's built-in reference attack"),
    )
    parser.add_argument(
        "--mode",
        choices=("both", "protected", "unprotected"),
        default="both",
        help="which execution mode(s) to evaluate",
    )
    parser.add_argument(
        "--fail-on-protected-violation",
        action="store_true",
        help="return exit code 2 if any evaluated protected episode violates an invariant",
    )
    parser.add_argument(
        "--fail-on-clean-utility-loss",
        action="store_true",
        help="return exit code 3 if any observable clean baseline fails its utility oracle",
    )
    parser.add_argument(
        "--fail-on-target-failure",
        action="store_true",
        help="return exit code 4 if any baseline or attacked target generation is invalid",
    )
    parser.add_argument(
        "--print-json-summary",
        action="store_true",
        help="also print the full machine-readable JSON summary after the concise table",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vais",
        description="VAIS deterministic enforcement and adaptive security verification tools.",
    )
    from ._version import __version__
    parser.add_argument("--version", "-V", action="version", version=f"vais {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy = subparsers.add_parser("validate-policy", help="strictly validate a policy YAML file")
    policy.add_argument("path")

    invariants = subparsers.add_parser(
        "validate-invariants", help="strictly validate an invariant YAML file"
    )
    invariants.add_argument("path")

    benchmark = subparsers.add_parser(
        "benchmark-default",
        help="run the deterministic five-scenario adaptive-verification smoke benchmark",
    )
    _add_common_benchmark_args(benchmark, default_output="results/default-benchmark.jsonl")

    models = subparsers.add_parser(
        "list-lmstudio-models",
        help="list models and capabilities from LM Studio's native model catalog",
    )
    models.add_argument(
        "--server-url",
        "--base-url",
        dest="server_url",
        default="http://localhost:1234",
        help="LM Studio server root (default: http://localhost:1234)",
    )
    models.add_argument("--timeout", type=float, default=30.0)
    models.add_argument(
        "--json",
        action="store_true",
        help="print native catalog entries as JSON instead of model IDs",
    )

    lmstudio = subparsers.add_parser(
        "benchmark-lmstudio",
        help="run the five-scenario benchmark against one or more real LM Studio models",
    )
    lmstudio.add_argument(
        "--model",
        required=True,
        action="append",
        help="LM Studio model identifier; repeat --model to compare multiple targets",
    )
    lmstudio.add_argument(
        "--server-url",
        default="http://localhost:1234",
        help="LM Studio server root used for native metadata",
    )
    lmstudio.add_argument(
        "--base-url",
        default="http://localhost:1234/v1",
        help="OpenAI-compatible base URL used for structured target inference",
    )
    lmstudio.add_argument("--timeout", type=float, default=120.0)
    lmstudio.add_argument("--temperature", type=float, default=0.0)
    lmstudio.add_argument("--max-tokens", type=int, default=2048)
    lmstudio.add_argument(
        "--transport-retries",
        type=int,
        default=1,
        help="retry only timeout/transport failures; model-plan failures are never retried",
    )
    lmstudio.add_argument(
        "--reasoning-mode",
        choices=("off", "low", "medium", "high", "on", "auto"),
        default=None,
        help=(
            "record the operator-configured reasoning mode in experiment metadata; "
            "the OpenAI-compatible adapter does not enforce this setting"
        ),
    )
    lmstudio.add_argument(
        "--disable-thinking",
        action="store_true",
        help=(
            "DEPRECATED best-effort chat-template switch; not portable/reliable. "
            "Configure reasoning in LM Studio and use --reasoning-mode to label the run."
        ),
    )
    _add_common_benchmark_args(lmstudio, default_output="results/lmstudio-benchmark.jsonl")

    mcp_default = subparsers.add_parser(
        "benchmark-mcp-default",
        help=(
            "run the 125-case MCP-path benchmark against deterministic harness targets; "
            "attacks arrive as untrusted MCP tool-result data"
        ),
    )
    _add_common_benchmark_args(
        mcp_default, default_output="results/mcp-default-benchmark.jsonl"
    )
    mcp_default.set_defaults(attack_corpus="bundled:v0.8-mcp")

    mcp_lmstudio = subparsers.add_parser(
        "benchmark-mcp-lmstudio",
        help=(
            "run the MCP-path security benchmark against one or more LM Studio models; "
            "outbound actions use unprotected/protected MCP clients"
        ),
    )
    mcp_lmstudio.add_argument(
        "--model", required=True, action="append",
        help="LM Studio model identifier; repeat --model to compare multiple targets",
    )
    mcp_lmstudio.add_argument(
        "--server-url", default="http://localhost:1234",
        help="LM Studio server root used for native metadata",
    )
    mcp_lmstudio.add_argument(
        "--base-url", default="http://localhost:1234/v1",
        help="OpenAI-compatible base URL used for structured target inference",
    )
    mcp_lmstudio.add_argument("--timeout", type=float, default=120.0)
    mcp_lmstudio.add_argument("--temperature", type=float, default=0.0)
    mcp_lmstudio.add_argument("--max-tokens", type=int, default=2048)
    mcp_lmstudio.add_argument(
        "--transport-retries", type=int, default=1,
        help="retry only timeout/transport failures; model-plan failures are never retried",
    )
    mcp_lmstudio.add_argument(
        "--reasoning-mode",
        choices=("off", "low", "medium", "high", "on", "auto"),
        default=None,
        help=(
            "record the operator-configured reasoning mode in experiment metadata; "
            "the adapter does not enforce this setting"
        ),
    )
    mcp_lmstudio.add_argument(
        "--disable-thinking", action="store_true",
        help=(
            "DEPRECATED best-effort chat-template switch; configure reasoning in LM Studio "
            "and use --reasoning-mode to label the run"
        ),
    )
    _add_common_benchmark_args(
        mcp_lmstudio, default_output="results/mcp-lmstudio-benchmark.jsonl"
    )
    mcp_lmstudio.set_defaults(attack_corpus="bundled:v0.8-mcp")

    mcp_profile = subparsers.add_parser(
        "validate-mcp-profile",
        help="strictly validate an MCP integration profile",
    )
    mcp_profile.add_argument("path")

    subparsers.add_parser(
        "mcp-demo",
        help="run the deterministic VAIS MCP security-boundary demonstration",
    )


    reference_default = subparsers.add_parser(
        "reference-agent-default",
        help=(
            "run the v0.9.3 stateful incident-response reference system against "
            "deterministic targets (5 clean workflows + 20 attack stories)"
        ),
    )
    reference_default.add_argument(
        "--output", default="results/reference-agent-default-v093.jsonl",
        help="JSONL trace output path",
    )
    reference_default.add_argument(
        "--summary", default="results/reference-agent-default-v093-summary.json",
        help="JSON summary output path",
    )
    reference_default.add_argument(
        "--print-json-summary", action="store_true",
        help="also print the machine-readable summary",
    )

    reference_lmstudio = subparsers.add_parser(
        "reference-agent-lmstudio",
        help=(
            "run the v0.9.3 stateful incident-response reference system against "
            "one or more LM Studio models"
        ),
    )
    reference_lmstudio.add_argument(
        "--model", required=True, action="append",
        help="LM Studio model identifier; repeat --model to compare targets",
    )
    reference_lmstudio.add_argument("--base-url", default="http://localhost:1234/v1")
    reference_lmstudio.add_argument("--timeout", type=float, default=120.0)
    reference_lmstudio.add_argument("--temperature", type=float, default=0.0)
    reference_lmstudio.add_argument("--max-tokens", type=int, default=2048)
    reference_lmstudio.add_argument("--transport-retries", type=int, default=1)
    reference_lmstudio.add_argument(
        "--reasoning-mode",
        choices=("off", "low", "medium", "high", "on", "auto"),
        default=None,
        help=(
            "record the operator-configured reasoning mode; the adapter does not enforce it"
        ),
    )
    reference_lmstudio.add_argument(
        "--disable-thinking", action="store_true",
        help="request LM Studio reasoning_effort=none; observed reasoning remains the conformance authority",
    )
    reference_lmstudio.add_argument(
        "--output", default="results/reference-agent-lmstudio-v093.jsonl",
        help="JSONL trace output path",
    )
    reference_lmstudio.add_argument(
        "--summary", default="results/reference-agent-lmstudio-v093-summary.json",
        help="JSON summary output path",
    )
    reference_lmstudio.add_argument(
        "--print-json-summary", action="store_true",
        help="also print the machine-readable summary",
    )

    adaptive_default = subparsers.add_parser(
        "adaptive-reference-default",
        help=(
            "run v0.10 adaptive verification against the frozen v0.9.3 reference "
            "system using deterministic mutation search and a deterministic adaptive target"
        ),
    )
    adaptive_default.add_argument("--episodes", type=int, default=12, help="maximum adaptive episodes per attack story")
    adaptive_default.add_argument("--search-mode", choices=("adaptive", "fixed"), default="adaptive", help="feedback-guided adaptive mutation search or fixed-seed ablation")
    adaptive_default.add_argument("--scenario", action="append", default=None, help="reference attack workflow ID, e.g. attack-09; repeat to select multiple; default all 20")
    adaptive_default.add_argument("--include-unprotected-diagnostic", action="store_true", help="also execute each candidate unprotected for diagnostic comparison; never changes the protected terminal security reward")
    adaptive_default.add_argument("--continue-after-violation", action="store_true", help="continue a campaign after terminal security reward reaches 1")
    adaptive_default.add_argument("--output", default="results/adaptive-reference-default-v010.jsonl", help="adaptive episode JSONL output path")
    adaptive_default.add_argument("--summary", default="results/adaptive-reference-default-v010-summary.json", help="adaptive summary JSON path")
    adaptive_default.add_argument("--rlvr-output", default="results/adaptive-reference-default-v010-rlvr.jsonl", help="RLVR-compatible trajectory JSONL path")
    adaptive_default.add_argument("--print-json-summary", action="store_true")
    adaptive_default.add_argument("--overwrite", action="store_true", help="replace existing output artifacts")
    adaptive_default.add_argument("--fail-on-protected-violation", action="store_true", help="return exit code 2 if adaptive verification discovers a protected invariant violation")

    adaptive_lmstudio = subparsers.add_parser(
        "adaptive-reference-lmstudio",
        help=(
            "run v0.10 adaptive verification against real LM Studio reference-agent "
            "targets; use deterministic mutation search or an optional LM Studio attacker model"
        ),
    )
    adaptive_lmstudio.add_argument("--target-model", required=True, action="append", help="LM Studio target model identifier; repeat to compare targets")
    adaptive_lmstudio.add_argument("--attacker-model", default=None, help="optional LM Studio attacker model; omit to use deterministic adaptive mutation search")
    adaptive_lmstudio.add_argument("--episodes", type=int, default=12, help="maximum adaptive episodes per attack story")
    adaptive_lmstudio.add_argument("--search-mode", choices=("adaptive", "fixed"), default="adaptive", help="feedback-guided adaptive mutation search or fixed-seed ablation; ignored when --attacker-model is used")
    adaptive_lmstudio.add_argument("--scenario", action="append", default=None, help="reference attack workflow ID, e.g. attack-09; repeat to select multiple; default all 20")
    adaptive_lmstudio.add_argument("--include-unprotected-diagnostic", action="store_true", help="also execute each candidate unprotected for diagnostic comparison")
    adaptive_lmstudio.add_argument("--continue-after-violation", action="store_true")
    adaptive_lmstudio.add_argument("--target-base-url", default="http://localhost:1234/v1")
    adaptive_lmstudio.add_argument("--attacker-base-url", default=None, help="OpenAI-compatible attacker endpoint; default target-base-url")
    adaptive_lmstudio.add_argument("--timeout", type=float, default=120.0)
    adaptive_lmstudio.add_argument("--target-temperature", type=float, default=0.0)
    adaptive_lmstudio.add_argument("--attacker-temperature", type=float, default=0.7)
    adaptive_lmstudio.add_argument("--target-max-tokens", type=int, default=2048)
    adaptive_lmstudio.add_argument("--target-truncation-retry-tokens", type=int, default=None, help="retry one length-truncated target generation with this larger max_tokens budget; disabled by default")
    adaptive_lmstudio.add_argument("--attacker-max-tokens", type=int, default=768)
    adaptive_lmstudio.add_argument("--transport-retries", type=int, default=1)
    adaptive_lmstudio.add_argument("--target-reasoning-mode", choices=("off", "low", "medium", "high", "on", "auto"), default=None)
    adaptive_lmstudio.add_argument("--attacker-reasoning-mode", choices=("off", "low", "medium", "high", "on", "auto"), default=None)
    adaptive_lmstudio.add_argument("--target-disable-thinking", action="store_true", help="request LM Studio target reasoning_effort=none; observed output remains authoritative")
    adaptive_lmstudio.add_argument("--attacker-disable-thinking", action="store_true", help="request LM Studio attacker reasoning_effort=none; observed output remains authoritative")
    adaptive_lmstudio.add_argument("--output", default="results/adaptive-reference-lmstudio-v010.jsonl")
    adaptive_lmstudio.add_argument("--summary", default="results/adaptive-reference-lmstudio-v010-summary.json")
    adaptive_lmstudio.add_argument("--rlvr-output", default="results/adaptive-reference-lmstudio-v010-rlvr.jsonl")
    adaptive_lmstudio.add_argument("--print-json-summary", action="store_true")
    adaptive_lmstudio.add_argument("--overwrite", action="store_true", help="replace existing output artifacts")
    adaptive_lmstudio.add_argument("--fail-on-protected-violation", action="store_true", help="return exit code 2 if adaptive verification discovers a protected invariant violation")
    adaptive_lmstudio.add_argument("--fail-on-target-failure", action="store_true", help="return exit code 4 if any target generation makes an episode unevaluable")
    adaptive_lmstudio.add_argument(
        "--fail-on-reasoning-mode-mismatch",
        action="store_true",
        help=(
            "return exit code 5 when observed reasoning does not conform to the "
            "declared target reasoning mode"
        ),
    )

    audit_results = subparsers.add_parser(
        "audit-results",
        help="offline reclassify stored episode JSONL using current measurement semantics",
    )
    audit_results.add_argument("path", help="existing VAIS episode JSONL")
    audit_results.add_argument("--output", default=None, help="optional JSON audit report path")
    audit_results.add_argument(
        "--print-json",
        action="store_true",
        help="also print the full machine-readable audit JSON",
    )

    research_build = subparsers.add_parser(
        "research-build",
        help="build the VAIS Research Evidence Base from historical release/experiment roots",
    )
    research_build.add_argument(
        "--root", action="append", default=[],
        help="historical VAIS directory or artifact path to index; repeat for multiple roots",
    )
    research_build.add_argument(
        "--history-root", action="append", default=[],
        help="directory whose immediate vais-v* children should be indexed; repeat as needed",
    )
    research_build.add_argument(
        "--research-dir", default="research",
        help="canonical research directory containing knowledge/*.yaml (default: research)",
    )
    research_build.add_argument(
        "--db", default=None,
        help="SQLite output path (default: <research-dir>/db/vais-research.sqlite)",
    )
    research_build.add_argument("--json", action="store_true", help="print build result as JSON")

    research_summary_parser = subparsers.add_parser(
        "research-summary", help="summarize an existing VAIS Research Evidence Base database"
    )
    research_summary_parser.add_argument("--db", default="research/db/vais-research.sqlite")
    research_summary_parser.add_argument("--json", action="store_true")

    research_query_parser = subparsers.add_parser(
        "research-query", help="query claims/findings/decisions/limitations and experiment metrics"
    )
    research_query_parser.add_argument("term")
    research_query_parser.add_argument("--db", default="research/db/vais-research.sqlite")
    research_query_parser.add_argument("--limit", type=int, default=20)

    research_doctor_parser = subparsers.add_parser(
        "research-doctor", help="audit research-evidence integrity, archive duplication and claim coverage"
    )
    research_doctor_parser.add_argument("--db", default="research/db/vais-research.sqlite")
    research_doctor_parser.add_argument("--duplicates", type=int, default=10, help="number of duplicate-content groups to show (default: 10)")
    research_doctor_parser.add_argument("--json", action="store_true", help="print the full machine-readable doctor report")
    research_doctor_parser.add_argument("--strict", action="store_true", help="return exit code 2 for unexpected unresolved evidence, hash mismatches, or evidence-less supported claims/findings")

    rc_plan = subparsers.add_parser("rc-benchmark-plan", help="validate the frozen RC model panel and write staged PowerShell campaign commands")
    rc_plan.add_argument("--manifest", default=None, help="manifest path; defaults to the packaged v0.12 panel")
    rc_plan.add_argument("--stage", choices=("preflight", "qualification", "screening", "full"), required=True)
    rc_plan.add_argument("--output", required=True)

    rc_report = subparsers.add_parser("rc-report", help="aggregate completed adaptive summaries and render the RC report bundle")
    rc_report.add_argument("--manifest", default=None, help="manifest path; defaults to the packaged v0.12 panel")
    rc_report.add_argument("--stage", choices=("preflight", "qualification", "screening", "full"), default="full")
    rc_report.add_argument("--summary", action="append", default=[], help="one single-target adaptive summary; repeat as needed")
    rc_report.add_argument("--output-dir", default="results/rc/report")

    evidence_report = subparsers.add_parser(
        "benchmark-report",
        help="verify an immutable benchmark checkpoint and render explanatory public-safe reports",
    )
    evidence_report.add_argument("--state", required=True, help="benchmark-state.json checkpoint")
    evidence_report.add_argument(
        "--manifest", required=True,
        help="exact panel manifest, or a report evidence manifest embedding the exact panel manifest",
    )
    evidence_report.add_argument(
        "--artifact-root", default=".",
        help="root used to resolve artifact paths stored in the checkpoint (default: current directory)",
    )
    evidence_report.add_argument("--output-dir", default="results/rc/report")

    benchmark_all = subparsers.add_parser(
        "benchmark",
        help="validate, run or resume the frozen local LM Studio model panel and render reports",
    )
    benchmark_scope = benchmark_all.add_mutually_exclusive_group(required=True)
    benchmark_scope.add_argument(
        "--all", action="store_true", help="run or resume every model in the frozen panel"
    )
    benchmark_scope.add_argument(
        "--model", action="append", help="run or resume one panel model ID; repeat as needed"
    )
    benchmark_all.add_argument("--manifest", default=None, help="manifest path; defaults to the packaged panel")
    benchmark_all.add_argument("--output-dir", default="results/rc", help="checkpoint and experiment artifact directory")
    benchmark_all.add_argument("--report-dir", default="results/rc/report", help="continuously regenerated report bundle")
    benchmark_all.add_argument("--target-base-url", default="http://localhost:1234/v1")
    benchmark_all.add_argument("--timeout", type=float, default=120.0)
    benchmark_all.add_argument("--target-max-tokens", type=int, default=2048)
    benchmark_all.add_argument("--transport-retries", type=int, default=1)
    benchmark_all.add_argument("--lms-executable", default="lms")
    benchmark_all.add_argument(
        "--dry-run", action="store_true",
        help="validate the server, complete inventory, quantizations and frozen configuration without loading or evaluating models",
    )

    subparsers.add_parser("version", help="print the installed VAIS version")
    return parser


def _modes(value: str):
    from .benchmark import ProtectionMode

    if value == "both":
        return (ProtectionMode.UNPROTECTED, ProtectionMode.PROTECTED)
    if value == "protected":
        return (ProtectionMode.PROTECTED,)
    return (ProtectionMode.UNPROTECTED,)


def _attackers(path: str | None):
    from .adaptive import ScenarioStaticAttacker, corpus_entry_attackers, load_attack_corpus

    if path:
        if path == "bundled:v0.6":
            bundled = Path(__file__).resolve().parent / "data" / "static_v0_6_125.jsonl"
            return corpus_entry_attackers(load_attack_corpus(bundled))
        if path == "bundled:v0.8-mcp":
            bundled = Path(__file__).resolve().parent / "data" / "mcp_static_v0_8_125.jsonl"
            return corpus_entry_attackers(load_attack_corpus(bundled))
        return corpus_entry_attackers(load_attack_corpus(path))
    return (ScenarioStaticAttacker(),)


def _output_guard(paths: Sequence[str | Path], *, overwrite: bool) -> str | None:
    resolved = [Path(path).resolve() for path in paths]
    if len(resolved) != len(set(resolved)):
        return "refusing to use the same path for multiple output artifacts"
    if overwrite:
        return None
    existing = [str(path) for path in resolved if path.exists()]
    if existing:
        return "refusing to overwrite existing output artifact(s): " + ", ".join(existing)
    return None


def _write_and_check(args, results) -> int:
    from .benchmark import ProtectionMode, summarize_results, write_results_jsonl

    write_results_jsonl(results, args.output)
    summary = summarize_results(results)
    rendered = json.dumps(summary, indent=2, sort_keys=True)
    from .reporting import render_console_summary

    print(render_console_summary(summary))
    if args.print_json_summary:
        print("\nMachine-readable summary\n" + rendered)
    print(f"wrote {len(results)} episodes to {args.output}")
    if args.summary:
        path = Path(args.summary)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote summary to {args.summary}")

    if args.fail_on_protected_violation and any(
        item.security_evaluated
        and item.mode == ProtectionMode.PROTECTED
        and item.violations
        for item in results
    ):
        print("security regression: protected invariant violation detected")
        return 2
    if args.fail_on_clean_utility_loss and any(
        item.clean_utility_success is False for item in results
    ):
        print("utility regression: clean baseline failed")
        return 3
    if args.fail_on_target_failure and any(
        not item.baseline_generation.valid or not item.candidate_generation.valid
        for item in results
    ):
        print("target regression: invalid/truncated/failed target generation detected")
        return 4
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.command == "validate-policy":
        policy = load_policy(args.path)
        print(f"valid policy: schema={policy.version} tools={len(policy.tools)}")
        return 0

    if args.command == "validate-invariants":
        engine = load_invariants(args.path)
        print(f"valid invariants: count={len(engine.invariants)}")
        return 0

    if args.command == "validate-mcp-profile":
        from .mcp import load_mcp_profile

        profile = load_mcp_profile(args.path)
        print(f"valid MCP profile: schema={profile.version} tools={len(profile.bindings)}")
        return 0

    if args.command == "mcp-demo":
        import asyncio
        from .mcp_demo import run_demo

        asyncio.run(run_demo())
        return 0

    if args.command == "benchmark-default":
        from .adaptive import DeterministicScenarioTarget
        from .benchmark import BenchmarkRunner
        from .scenarios import default_scenarios

        targets = (
            DeterministicScenarioTarget("deterministic-vulnerable"),
            DeterministicScenarioTarget(
                "deterministic-selective",
                susceptible_scenarios={
                    "email-recipient-hijack",
                    "forbidden-tool-escalation",
                    "approval-replay",
                },
            ),
        )
        results = BenchmarkRunner().run_matrix(
            scenarios=default_scenarios(),
            targets=targets,
            attackers=_attackers(args.attack_corpus),
            modes=_modes(args.mode),
        )
        return _write_and_check(args, results)

    if args.command == "list-lmstudio-models":
        from .openai_compatible import list_lmstudio_models

        models = list_lmstudio_models(
            server_url=args.server_url,
            timeout_seconds=args.timeout,
        )
        if args.json:
            print(json.dumps(models, indent=2, sort_keys=True))
        elif not models:
            print("no models reported by LM Studio")
        else:
            for model in models:
                key = model.get("key", "<unknown>")
                quant = model.get("quantization")
                quant_name = quant.get("name") if isinstance(quant, dict) else None
                params = model.get("params_string")
                capabilities = model.get("capabilities")
                reasoning = None
                if isinstance(capabilities, dict) and isinstance(capabilities.get("reasoning"), dict):
                    reasoning = capabilities["reasoning"].get("default")
                suffix = " ".join(
                    item
                    for item in (
                        f"params={params}" if params else "",
                        f"quant={quant_name}" if quant_name else "",
                        f"reasoning_default={reasoning}" if reasoning else "",
                    )
                    if item
                )
                print(f"{key}{'  ' + suffix if suffix else ''}")
        return 0

    if args.command == "benchmark-lmstudio":
        from .benchmark import BenchmarkRunner
        from .openai_compatible import LMStudioTarget, lmstudio_config_from_env
        from .scenarios import default_scenarios

        targets = tuple(
            LMStudioTarget(
                lmstudio_config_from_env(
                    model,
                    base_url=args.base_url,
                    timeout_seconds=args.timeout,
                    temperature=args.temperature,
                    max_tokens=args.max_tokens,
                    disable_thinking=args.disable_thinking,
                    transport_retries=args.transport_retries,
                    reasoning_mode_label=args.reasoning_mode,
                ),
                server_url=args.server_url,
            )
            for model in args.model
        )
        results = BenchmarkRunner().run_matrix(
            scenarios=default_scenarios(),
            targets=targets,
            attackers=_attackers(args.attack_corpus),
            modes=_modes(args.mode),
        )
        return _write_and_check(args, results)

    if args.command == "benchmark-mcp-default":
        import asyncio
        from .mcp_benchmark import MCPBenchmarkRunner, MCPDeterministicScenarioTarget
        from .scenarios import default_scenarios

        targets = (
            MCPDeterministicScenarioTarget("deterministic-mcp-vulnerable"),
            MCPDeterministicScenarioTarget(
                "deterministic-mcp-selective",
                susceptible_scenarios={
                    "email-recipient-hijack",
                    "forbidden-tool-escalation",
                    "approval-replay",
                },
            ),
        )
        results = asyncio.run(
            MCPBenchmarkRunner().run_matrix(
                scenarios=default_scenarios(),
                targets=targets,
                attackers=_attackers(args.attack_corpus),
                modes=_modes(args.mode),
            )
        )
        return _write_and_check(args, results)

    if args.command == "benchmark-mcp-lmstudio":
        import asyncio
        from .mcp_benchmark import MCPBenchmarkRunner
        from .openai_compatible import LMStudioTarget, lmstudio_config_from_env
        from .scenarios import default_scenarios

        targets = tuple(
            LMStudioTarget(
                lmstudio_config_from_env(
                    model,
                    base_url=args.base_url,
                    timeout_seconds=args.timeout,
                    temperature=args.temperature,
                    max_tokens=args.max_tokens,
                    disable_thinking=args.disable_thinking,
                    transport_retries=args.transport_retries,
                    reasoning_mode_label=args.reasoning_mode,
                ),
                server_url=args.server_url,
            )
            for model in args.model
        )
        results = asyncio.run(
            MCPBenchmarkRunner().run_matrix(
                scenarios=default_scenarios(),
                targets=targets,
                attackers=_attackers(args.attack_corpus),
                modes=_modes(args.mode),
            )
        )
        return _write_and_check(args, results)


    if args.command == "reference-agent-default":
        import asyncio
        from .reference_agent import (
            DeterministicReferenceTarget,
            ReferenceAgentRunner,
            SelectiveReferenceTarget,
            reference_workflows,
            summarize_reference_results,
            write_reference_results_jsonl,
        )
        from .reporting import render_reference_agent_summary

        targets = (DeterministicReferenceTarget(), SelectiveReferenceTarget())
        results = asyncio.run(
            ReferenceAgentRunner().run_matrix(reference_workflows(), targets)
        )
        write_reference_results_jsonl(results, args.output)
        summary = summarize_reference_results(results)
        rendered = json.dumps(summary, indent=2, sort_keys=True)
        print(render_reference_agent_summary(summary))
        if args.print_json_summary:
            print("\nMachine-readable summary\n" + rendered)
        path = Path(args.summary)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {len(results)} workflow traces to {args.output}")
        print(f"wrote summary to {args.summary}")
        return 0

    if args.command == "reference-agent-lmstudio":
        import asyncio
        from .openai_compatible import lmstudio_config_from_env
        from .reference_agent import (
            ReferenceAgentRunner,
            reference_workflows,
            summarize_reference_results,
            write_reference_results_jsonl,
        )
        from .reference_agent_lmstudio import ReferenceAgentLMStudioTarget
        from .reporting import render_reference_agent_summary

        targets = tuple(
            ReferenceAgentLMStudioTarget(
                lmstudio_config_from_env(
                    model,
                    base_url=args.base_url,
                    timeout_seconds=args.timeout,
                    temperature=args.temperature,
                    max_tokens=args.max_tokens,
                    disable_thinking=args.disable_thinking,
                    transport_retries=args.transport_retries,
                    reasoning_mode_label=args.reasoning_mode,
                )
            )
            for model in args.model
        )
        results = asyncio.run(
            ReferenceAgentRunner().run_matrix(reference_workflows(), targets)
        )
        write_reference_results_jsonl(results, args.output)
        summary = summarize_reference_results(results)
        rendered = json.dumps(summary, indent=2, sort_keys=True)
        print(render_reference_agent_summary(summary))
        if args.print_json_summary:
            print("\nMachine-readable summary\n" + rendered)
        path = Path(args.summary)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {len(results)} workflow traces to {args.output}")
        print(f"wrote summary to {args.summary}")
        return 0

    if args.command == "adaptive-reference-default":
        import asyncio
        from .adaptive_reference import (
            AdaptiveReferenceVerifier,
            AdaptiveVerifierConfig,
            FixedMutationSearchAttacker,
            MutationSearchAttacker,
            PatternAdaptiveReferenceTarget,
            selected_attack_workflows,
            summarize_adaptive_campaigns,
            write_adaptive_results_jsonl,
            write_rlvr_trajectories,
        )
        from .reporting import render_adaptive_reference_summary

        output_error = _output_guard(
            (args.output, args.summary, args.rlvr_output), overwrite=args.overwrite
        )
        if output_error:
            print(output_error + "; pass --overwrite to replace them")
            return 6
        workflows = selected_attack_workflows(args.scenario)
        config = AdaptiveVerifierConfig(
            episodes_per_campaign=args.episodes,
            stop_on_violation=not args.continue_after_violation,
            include_unprotected_diagnostic=args.include_unprotected_diagnostic,
        )
        verifier = AdaptiveReferenceVerifier(config=config)
        target = PatternAdaptiveReferenceTarget()
        campaigns = asyncio.run(
            verifier.run_matrix(
                workflows,
                (target,),
                lambda _target, _workflow: (FixedMutationSearchAttacker() if args.search_mode == "fixed" else MutationSearchAttacker()),
            )
        )
        write_adaptive_results_jsonl(campaigns, args.output)
        write_rlvr_trajectories(campaigns, args.rlvr_output)
        summary = summarize_adaptive_campaigns(campaigns)
        rendered = json.dumps(summary, indent=2, sort_keys=True)
        print(render_adaptive_reference_summary(summary))
        if args.print_json_summary:
            print("\nMachine-readable summary\n" + rendered)
        path = Path(args.summary)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {sum(len(item.episodes) for item in campaigns)} adaptive episodes to {args.output}")
        print(f"wrote RLVR-compatible trajectories to {args.rlvr_output}")
        print(f"wrote summary to {args.summary}")
        if args.fail_on_protected_violation and any(
            episode.terminal_security_reward == 1.0
            for campaign in campaigns
            for episode in campaign.episodes
        ):
            return 2
        return 0

    if args.command == "adaptive-reference-lmstudio":
        import asyncio
        from .adaptive_reference import (
            AdaptiveReferenceVerifier,
            AdaptiveVerifierConfig,
            LMStudioAdaptiveAttacker,
            FixedMutationSearchAttacker,
            MutationSearchAttacker,
            selected_attack_workflows,
            summarize_adaptive_campaigns,
            write_adaptive_results_jsonl,
            write_rlvr_trajectories,
        )
        from .openai_compatible import lmstudio_config_from_env
        from .reference_agent_lmstudio import ReferenceAgentLMStudioTarget
        from .reporting import render_adaptive_reference_summary

        output_error = _output_guard(
            (args.output, args.summary, args.rlvr_output), overwrite=args.overwrite
        )
        if output_error:
            print(output_error + "; pass --overwrite to replace them")
            return 6
        workflows = selected_attack_workflows(args.scenario)
        config = AdaptiveVerifierConfig(
            episodes_per_campaign=args.episodes,
            stop_on_violation=not args.continue_after_violation,
            include_unprotected_diagnostic=args.include_unprotected_diagnostic,
        )
        targets = tuple(
            ReferenceAgentLMStudioTarget(
                lmstudio_config_from_env(
                    model,
                    base_url=args.target_base_url,
                    timeout_seconds=args.timeout,
                    temperature=args.target_temperature,
                    max_tokens=args.target_max_tokens,
                    disable_thinking=args.target_disable_thinking,
                    transport_retries=args.transport_retries,
                    reasoning_mode_label=args.target_reasoning_mode,
                    truncation_retry_tokens=args.target_truncation_retry_tokens,
                )
            )
            for model in args.target_model
        )

        def attacker_factory(_target, _workflow):
            if args.attacker_model is None:
                return FixedMutationSearchAttacker() if args.search_mode == "fixed" else MutationSearchAttacker()
            return LMStudioAdaptiveAttacker(
                lmstudio_config_from_env(
                    args.attacker_model,
                    base_url=args.attacker_base_url or args.target_base_url,
                    timeout_seconds=args.timeout,
                    temperature=args.attacker_temperature,
                    max_tokens=args.attacker_max_tokens,
                    disable_thinking=args.attacker_disable_thinking,
                    transport_retries=args.transport_retries,
                    reasoning_mode_label=args.attacker_reasoning_mode,
                )
            )

        campaigns = asyncio.run(
            AdaptiveReferenceVerifier(config=config).run_matrix(
                workflows, targets, attacker_factory
            )
        )
        write_adaptive_results_jsonl(campaigns, args.output)
        write_rlvr_trajectories(campaigns, args.rlvr_output)
        summary = summarize_adaptive_campaigns(campaigns)
        rendered = json.dumps(summary, indent=2, sort_keys=True)
        print(render_adaptive_reference_summary(summary))
        if args.print_json_summary:
            print("\nMachine-readable summary\n" + rendered)
        path = Path(args.summary)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {sum(len(item.episodes) for item in campaigns)} adaptive episodes to {args.output}")
        print(f"wrote RLVR-compatible trajectories to {args.rlvr_output}")
        print(f"wrote summary to {args.summary}")
        if args.fail_on_protected_violation and any(
            episode.terminal_security_reward == 1.0
            for campaign in campaigns
            for episode in campaign.episodes
        ):
            return 2
        if args.fail_on_target_failure and any(
            episode.target_failure
            for campaign in campaigns
            for episode in campaign.episodes
        ):
            print("target regression: at least one adaptive episode was unevaluable")
            return 4
        if args.fail_on_reasoning_mode_mismatch and any(
            metrics.get("reasoning_mode_mismatch")
            for metrics in summary["by_target"].values()
        ):
            print("configuration regression: observed output contradicted the declared target reasoning mode")
            return 5
        return 0

    if args.command == "audit-results":
        from .reanalysis import audit_stored_results

        report = audit_stored_results(args.path)
        rendered = json.dumps(report, indent=2, sort_keys=True)
        from .reporting import render_audit_summary

        print(render_audit_summary(report))
        if args.print_json:
            print("\nMachine-readable audit\n" + rendered)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered + "\n", encoding="utf-8")
            print(f"wrote audit report to {args.output}")
        return 0

    if args.command == "rc-benchmark-plan":
        from .rc_benchmark import build_campaign_plan, load_rc_manifest
        manifest = load_rc_manifest(args.manifest)
        output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(build_campaign_plan(manifest, args.stage), encoding="utf-8")
        print(f"validated {len(manifest['models'])} models across {len({m['family'] for m in manifest['models']})} families")
        print(f"wrote {args.stage} campaign plan to {output}")
        return 0

    if args.command == "rc-report":
        from .rc_benchmark import aggregate_rc_summaries, load_rc_manifest, write_rc_report_bundle
        aggregate = aggregate_rc_summaries(
            load_rc_manifest(args.manifest), args.summary, stage=args.stage
        )
        write_rc_report_bundle(aggregate, args.output_dir)
        print(f"rendered RC report bundle: {aggregate['models_completed']}/{aggregate['models_planned']} models completed")
        print(f"output: {args.output_dir}")
        return 0

    if args.command == "benchmark-report":
        from ._version import __version__
        from .rc_benchmark import load_rc_manifest, render_checkpoint_report
        try:
            aggregate = render_checkpoint_report(
                load_rc_manifest(args.manifest),
                args.state,
                args.output_dir,
                artifact_root=args.artifact_root,
                renderer_version=__version__,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"benchmark report refused to render: {exc}")
            return 7
        integrity = aggregate.get("input_integrity", {})
        print(
            "verified immutable evidence: "
            f"{integrity.get('artifacts_verified', 0)} artifacts, "
            f"evidence {aggregate.get('evidence_version')}"
        )
        print(f"renderer: {aggregate.get('renderer_version')}")
        print(f"one-page summary: {Path(args.output_dir) / 'executive-summary.html'}")
        print(f"full report: {Path(args.output_dir) / 'benchmark-report.html'}")
        return 0

    if args.command == "benchmark":
        from .benchmark_automation import (
            AutomationOptions,
            BenchmarkAutomationError,
            LMStudioRuntime,
            run_benchmark_all,
        )
        from .rc_benchmark import load_rc_manifest

        try:
            options = AutomationOptions(
                output_dir=Path(args.output_dir),
                report_dir=Path(args.report_dir),
                target_base_url=args.target_base_url,
                timeout_seconds=args.timeout,
                target_max_tokens=args.target_max_tokens,
                transport_retries=args.transport_retries,
                dry_run=args.dry_run,
                model_ids=None if args.all else tuple(args.model or ()),
            )
            state, code = run_benchmark_all(
                load_rc_manifest(args.manifest),
                options,
                runtime=LMStudioRuntime(executable=args.lms_executable),
            )
        except (BenchmarkAutomationError, ValueError) as exc:
            print(f"benchmark automation refused to continue: {exc}")
            return 7
        completed = sum(
            model.get("status") == "completed" for model in state["models"].values()
        )
        print(f"benchmark status: {state['status']} ({completed}/{len(state['models'])} models completed)")
        print(f"checkpoint: {Path(args.output_dir) / 'benchmark-state.json'}")
        print(f"HTML report: {Path(args.report_dir) / 'benchmark-report.html'}")
        return code

    if args.command == "research-build":
        from .research import build_research_database, discover_history_roots

        roots = list(args.root)
        for history_root in args.history_root:
            roots.extend(str(path) for path in discover_history_roots(history_root))
        if not roots:
            print("research-build requires --root or --history-root")
            return 2
        result = build_research_database(
            roots, research_dir=args.research_dir, database=args.db
        )
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print("VAIS Research Evidence Base")
            print("=" * 40)
            print(f"database:      {result.database}")
            print(f"artifacts:     {result.artifacts}")
            print(f"experiments:   {result.experiments}")
            print(f"observations:  {result.observations}")
            print(f"claims:        {result.claims}")
            print(f"findings:      {result.findings}")
            print(f"decisions:     {result.decisions}")
            print(f"limitations:   {result.limitations}")
            print(f"sources:       {result.sources}")
            print(f"hypotheses:    {result.hypotheses}")
            print(f"evidence links:{result.evidence_links:>5} ({result.resolved_evidence_links} resolved)")
        return 0

    if args.command == "research-summary":
        from .research import research_summary

        summary = research_summary(args.db)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print("VAIS Research Evidence Base")
            print("=" * 40)
            for key, value in summary["counts"].items():
                print(f"{key + ':':16} {value}")
            content = summary["content_inventory"]
            print("content-addressed inventory")
            print(f"  unique artifact content:       {content['unique_artifact_contents']}")
            print(f"  content-addressed experiments: {content['content_addressed_experiments']}")
            print(f"  content-addressed observations:{content['content_addressed_observations']:>5}")
            print(f"  logical evidence references:   {content['logical_evidence_references']} ({content['resolved_logical_evidence_references']} resolved, {content['unresolved_logical_evidence_references']} unresolved)")
            print("experiment versions: " + ", ".join(summary["framework_versions"]))
            print("artifact versions:   " + ", ".join(summary["artifact_versions"]))
            print("targets:             " + ", ".join(summary["targets"]))
            print("modes:               " + ", ".join(f"{item['mode']}={item['experiments']}" for item in summary["modes"]))
            print("claim status:        " + ", ".join(f"{item['status']}={item['count']}" for item in summary["claim_status"]))
            print("hypothesis status:   " + ", ".join(f"{item['status']}={item['count']}" for item in summary["hypothesis_status"]))
            print(f"evidence link instances: {summary['resolved_evidence_links']} resolved, {summary['unresolved_evidence_links']} unresolved")
        return 0

    if args.command == "research-doctor":
        from .research import research_doctor

        report = research_doctor(args.db, duplicate_limit=args.duplicates)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            inv = report["content_inventory"]
            integrity = report["evidence_integrity"]
            knowledge = report["knowledge_integrity"]
            print("VAIS Research Doctor")
            print("=" * 72)
            print("Archive provenance")
            print(f"  artifact instances:             {inv['artifact_instances']}")
            print(f"  unique artifact content:        {inv['unique_artifact_contents']}")
            print(f"  duplicate artifact instances:   {inv['duplicate_artifact_instances']}")
            print(f"  duplicate content groups:       {inv['duplicate_artifact_groups']}")
            print(f"  experiment records:             {inv['experiment_records']}")
            print(f"  content-addressed experiments:  {inv['content_addressed_experiments']}")
            print(f"  observation records:            {inv['observation_records']}")
            print(f"  content-addressed observations: {inv['content_addressed_observations']}")
            print()
            print("Evidence integrity")
            print(f"  logical references:             {integrity['logical_references']}")
            print(f"  resolved logical references:    {integrity['resolved_logical_references']}")
            print(f"  expected external unresolved:   {integrity['expected_external_unresolved']}")
            print(f"  unexpected unresolved:          {integrity['unexpected_unresolved']}")
            print(f"  hash mismatches:                {integrity['hash_mismatches']}")
            if integrity["unresolved"]:
                print("  unresolved details:")
                for item in integrity["unresolved"]:
                    label = "expected-external" if item["expected_external"] else "UNEXPECTED"
                    print(f"    [{label}] {item['owner_type']}:{item['owner_id']} -> {item['evidence_ref']}")
                    if item.get("expected_sha256"):
                        print(f"      expected sha256: {item['expected_sha256']}")
            print()
            print("Knowledge integrity")
            print("  supported claims without resolved evidence: " + (", ".join(knowledge["supported_claims_without_resolved_evidence"]) or "none"))
            print("  findings without resolved evidence:         " + (", ".join(knowledge["findings_without_resolved_evidence"]) or "none"))
            print("  partially unresolved supported claims:      " + (", ".join(knowledge["partially_unresolved_supported_claims"]) or "none"))
            if report["duplicate_content_groups"]:
                print()
                print("Largest duplicate-content groups")
                for group in report["duplicate_content_groups"]:
                    print(f"  {group['copies']:>3} copies  {group['sha256'][:16]}…  {group['size_bytes']} bytes")
                    for path in group["sample_paths"][:2]:
                        print(f"      {path}")
            print()
            print("RESULT: " + ("research evidence integrity OK" if report["ok"] else f"{report['integrity_failures']} integrity issue(s) require attention"))
        if args.strict and not report["ok"]:
            return 2
        return 0

    if args.command == "research-query":
        from .research import research_query

        rows = research_query(args.db, args.term, limit=args.limit)
        if not rows:
            print("no matching research evidence")
            return 0
        for row in rows:
            table = row.pop("table", "evidence")
            print(f"[{table}] {row.get('id', '')}")
            text = row.get("claim") or row.get("finding") or row.get("decision") or row.get("limitation") or row.get("hypothesis") or row.get("definition") or row.get("title")
            if text:
                print(text)
            elif row.get("metrics_json"):
                print(f"version={row.get('framework_version')} target={row.get('target_id')} mode={row.get('mode')}")
                print(row["metrics_json"])
            print()
        return 0

    if args.command == "version":
        from ._version import __version__

        print(__version__)
        return 0

    raise AssertionError("unreachable")
