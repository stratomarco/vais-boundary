"""Replay every corpus trace with Dogwood and compare its decisions with VAIS's (PREREGISTRATION.md).

    PYTHONPATH=src python experiments/dogwood-expressibility/run.py --dogwood F:/dogwood/target/release/dogwood.exe

For each agent call, the Dogwood trace is: the trusted task events, the earlier calls (executed:
request and response; refused: an `error` event), and this call as a `request`. Trusted setup and
retrieval calls are the application's, so they enter history as executed and are not decided.
Writes results/decisions.json and results/summary.json.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
NAMESPACE = {"incident-response": "Inc", "accounts-payable": "Ap"}
REFUSED = {"deny", "require_approval"}


def lit(value) -> str:
    """A Cedar literal for a trace."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


def record(fields: dict) -> str:
    return "{ " + ", ".join(f"{k}: {lit(v)}" for k, v in sorted(fields.items())) + " }"


def cents(amount) -> int | None:
    try:
        return int((Decimal(str(amount)) * 100).to_integral_value())
    except (InvalidOperation, ValueError):
        return None


def call_input(arguments: dict) -> dict:
    fields = {k: (v if isinstance(v, str) else json.dumps(v, sort_keys=True)) for k, v in arguments.items()}
    if "amount" in arguments and cents(arguments["amount"]) is not None:
        fields["amount_cents"] = cents(arguments["amount"])
    return fields


def call_output(result) -> dict | None:
    if result is None:
        return None
    if isinstance(result, dict):
        return {k: (v if isinstance(v, str) else json.dumps(v, sort_keys=True)) for k, v in result.items()}
    return {"text": result if isinstance(result, str) else json.dumps(result, sort_keys=True)}


class Trace:
    def __init__(self, ns: str) -> None:
        self.ns, self.lines, self.t = ns, [], 0
        self.scope = f'scope(principal: {ns}::OAuthUser::"analyst", resource: {ns}::Gateway::"gw")'
        self.caller = f'callerPrincipal: {ns}::OAuthUser::"analyst", callerResource: {ns}::Gateway::"gw"'

    def event(self, action: str, kind: str, inp: dict, out: dict | None = None, *, current: bool = False) -> str:
        self.t += 1
        parts = [f"input: {record(inp)}"] + ([f"output: {record(out)}"] if out is not None else []) + [self.caller, f'requestId: "e{self.t}"']
        context = f" request_context(input: {record(inp)})" if current else ""
        return f'@{self.t} {self.scope}{context} {self.ns}::Action::"{action}"::{kind}({", ".join(parts)})'

    def add(self, *args, **kwargs) -> None:
        self.lines.append(self.event(*args, **kwargs))


def task_events(trace: Trace, workflow: dict, limits: dict) -> None:
    task = workflow["task"]
    ok = {"ok": True}
    for tool in task["allowed_tools"]:
        trace.add("TaskTool", "response", {"tool": tool}, ok)
    for scope in task["granted_scopes"]:
        trace.add("TaskScope", "response", {"scope": scope}, ok)
    for tool, args in task["bound"].items():
        for arg, value in args.items():
            trace.add("TaskBind", "response", {"tool": tool, "arg": arg, "value": str(value)}, ok)
    for tool, args in task["allowed_values"].items():
        for arg, spec in args.items():
            for value in spec["values"]:
                trace.add("TaskAllow", "response", {"tool": tool, "arg": arg, "value": str(value), "once": bool(spec["once"])}, ok)
    for tool, args in task["budgets"].items():
        for arg, cap in args.items():
            trace.add("TaskBudget", "response", {"tool": tool, "arg": arg, "cap": cents(cap)}, ok)
    for tool, args in task["value_budgets"].items():
        for arg, spec in args.items():
            for key, cap in spec["limits"].items():
                trace.add("TaskCap", "response", {"tool": tool, "arg": arg, "per": spec["per"], "key": key, "cap": cents(cap)}, ok)
    for tool, limit in limits.items():
        trace.add("TaskLimit", "response", {"tool": tool, "max": limit}, ok)
    for approved in task["approved"]:
        trace.add(f"Approved.{approved['tool']}", "response", call_input(approved["arguments"]), ok)


def decide(dogwood: str, policy: Path, schema: Path, lines: list[str]) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
        path = handle.name
    try:
        run = subprocess.run([dogwood, "replay", str(policy), "--policy-schema", str(schema), "--trace", path, "--format", "json"],
                             capture_output=True, text=True)
    finally:
        Path(path).unlink()
    if run.returncode != 0:
        return {"verdict": "error", "rules": [], "errors": [run.stderr.strip()[:500] or run.stdout.strip()[:500]]}
    last = json.loads(run.stdout)["verdicts"][-1]
    # Dogwood reports the determining rules in no fixed order; sorted, so the output is canonical.
    return {"verdict": last["verdict"], "rules": sorted(last["determining_rules"]), "errors": last["errors"]}


def replay(dogwood: str, workflow: dict, configuration: dict, policies: Path) -> list[dict]:
    app = workflow["application"]
    ns = NAMESPACE[app]
    policy, schema = policies / f"{app}.dw", policies / f"{app}.cedarschema"
    limits = {tool: rule["max_calls"] for tool, rule in configuration[app][workflow["id"]]["tools"].items()
              if rule["max_calls"] is not None and workflow["uses_ledger"]}
    history = Trace(ns)
    task_events(history, workflow, limits)
    decisions = []
    for call in workflow["calls"]:
        inp, out = call_input(call["arguments"]), call_output(call["result"])
        if not call["agent"]:
            history.add(call["tool"], "request", inp)
            history.add(call["tool"], "response", inp, out)
            continue
        probe = Trace(ns)
        probe.t = history.t
        lines = history.lines + [probe.event(call["tool"], "request", inp, current=True)]
        verdict = decide(dogwood, policy, schema, lines)
        history.t = probe.t
        if verdict["verdict"] == "allow":
            history.add(call["tool"], "request", inp)
            history.add(call["tool"], "response", inp, out)
        else:
            history.add(call["tool"], "error", inp)
        decisions.append({"index": call["index"], "tool": call["tool"], "vais": call["vais"]["type"],
                          "vais_reasons": call["vais"]["reasons"], "dogwood": verdict["verdict"],
                          "dogwood_rules": verdict["rules"], "dogwood_errors": verdict["errors"]})
    return decisions


def refused(decision: str) -> bool:
    return decision in REFUSED or decision == "error"


def summarize(corpus: list[dict], results: dict) -> dict:
    out: dict = {}
    for app in NAMESPACE:
        workflows = [w for w in corpus if w["application"] == app]
        table, benign, differing = {}, {}, []
        for w in workflows:
            decisions = results[f"{app}/{w['id']}"]
            if w["kind"] == "attack":
                upto = [d for d in decisions if d["index"] <= w["harmful_index"]]
                v = any(refused(d["vais"]) for d in upto)
                g = any(refused(d["dogwood"]) for d in upto)
                key = f"vais_{'refuses' if v else 'misses'}__dogwood_{'refuses' if g else 'misses'}"
                table[key] = table.get(key, 0) + 1
                if v != g:
                    differing.append({"workflow": w["id"], "category": w["category"], "vais_refuses": v, "dogwood_refuses": g})
            else:
                group = benign.setdefault(w["kind"], {"workflows": 0, "vais_completes": 0, "dogwood_completes": 0, "dogwood_refused": []})
                group["workflows"] += 1
                group["vais_completes"] += all(not refused(d["vais"]) for d in decisions)
                ok = all(not refused(d["dogwood"]) for d in decisions)
                group["dogwood_completes"] += ok
                if not ok:
                    group["dogwood_refused"].append(w["id"])
        calls = [d for w in workflows for d in results[f"{app}/{w['id']}"]]
        agree = sum(refused(d["vais"]) == refused(d["dogwood"]) for d in calls)
        looser = sum(refused(d["vais"]) and not refused(d["dogwood"]) for d in calls)
        stricter = sum(not refused(d["vais"]) and refused(d["dogwood"]) for d in calls)
        out[app] = {"attacks": table, "attacks_where_engines_differ": differing, "benign": benign,
                    "calls": {"total": len(calls), "agree": agree, "dogwood_looser": looser, "dogwood_stricter": stricter,
                              "dogwood_errors": sum(d["dogwood"] == "error" or bool(d["dogwood_errors"]) for d in calls)}}
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dogwood", required=True)
    parser.add_argument("--policies", type=Path, default=HERE / "policies")
    parser.add_argument("--results", type=Path, default=HERE / "results")
    args = parser.parse_args()
    corpus = json.loads((HERE / "corpus.json").read_text(encoding="utf-8"))["workflows"]
    configuration = json.loads((HERE / "configuration.json").read_text(encoding="utf-8"))
    results = {f"{w['application']}/{w['id']}": replay(args.dogwood, w, configuration, args.policies) for w in corpus}
    args.results.mkdir(parents=True, exist_ok=True)
    (args.results / "decisions.json").write_text(json.dumps(results, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    summary = summarize(corpus, results)
    (args.results / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
