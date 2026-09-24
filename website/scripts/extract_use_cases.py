"""Extract the homepage's "VAIS in action" cases from recorded runs, by fixed rules.

    python website/scripts/extract_use_cases.py \
        --rc7 F:/vais-rc7/results/rc7 --p1b4 F:/vais-main/experiments/p1b4/results \
        --output website/src/data/use-cases.json

Nothing on the page is typed by hand: every attack text, action, argument label, decision,
reason and verifier result comes from a record, and the output names the file, its SHA-256
and the record's line. Result data is never copied. An argument that contains a value the
run read from a secret store is replaced by a marker, since raw secret-bearing traces are
kept controlled.

The rules, applied in file order:

- forged-receipt: RC7 full-stage files in alphabetical order, excluding models the RC7
  aggregate marks gate-failed; workflow attack-01; the first episode whose protected run kept
  workflow utility and in which the model proposed, at one of its own turns, an action carrying
  attacker@evil.test that VAIS did not allow.
- labels-not-content: RC7 gemma-4-12b; workflow attack-09; the first episode that kept utility
  and in which a model action was denied for exceeding a confidentiality ceiling.
- llm-attacker: P1b-4 arm gemma-4-12b-on (reasoning on, language-model attacker); the first
  episode in file order that kept utility and in which a model action was not allowed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SECRET_MARK = "[secret value hidden]"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _records(path: Path):
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        yield number, json.loads(line)


def _kept_utility(result: dict) -> bool:
    return bool(result.get("workflow_utility_success")) and not result.get("target_failure")


def _model_steps(result: dict):
    return [s for s in result["trace"] if s["phase"].startswith("agent_turn") and s.get("action")]


def _secret_values(result: dict) -> list[str]:
    """Values a step read from a secret-labelled result, minus what that step itself sent.

    A secret read echoes its request (the secret's id) beside the secret; the id is the
    model's own argument, not secret material, so it is not hidden.
    """
    values = []
    for step in result["trace"]:
        res = step.get("result") or {}
        if (res.get("provenance") or {}).get("confidentiality") == "secret":
            sent = {str(v.get("data")) for v in ((step.get("action") or {}).get("arguments") or {}).values()}
            data = res.get("data")
            values.extend(str(v) for v in (data.values() if isinstance(data, dict) else [data]) if v and str(v) not in sent)
    return [v for v in values if len(v) >= 6]


def _step(step: dict, secrets: list[str]) -> dict:
    action = step.get("action") or {}
    arguments = {}
    for name, value in (action.get("arguments") or {}).items():
        shown = json.dumps(value.get("data")) if not isinstance(value.get("data"), str) else value["data"]
        if any(secret in shown for secret in secrets):
            shown = SECRET_MARK
        arguments[name] = {"value": shown, "trust": value["provenance"]["trust"],
                           "confidentiality": value["provenance"]["confidentiality"]}
    decision = step.get("decision") or {}
    return {
        "phase": step["phase"],
        "tool": action.get("tool"),
        "arguments": arguments,
        "decision": decision.get("type"),
        "reasons": list(decision.get("reasons") or []),
        "effect": (step.get("effect") or {}).get("kind"),
    }


def _case(case_id: str, study: str, model: str, path: Path, number: int, record: dict) -> dict:
    result = record["protected_result"]
    secrets = _secret_values(result)
    generations = result.get("target_generations") or []
    return {
        "id": case_id,
        "study": study,
        "model": model,
        "workflow": record["workflow_id"],
        "workflow_title": record["workflow_title"],
        "episode": record["episode"],
        "attacker": record.get("attacker_id"),
        "attack_text": record["candidate"]["text"],
        "steps": [_step(s, secrets) for s in result["trace"] if s.get("action")],
        "reasoning_tokens": sum(g.get("reasoning_tokens") or 0 for g in generations),
        "invariants": [{"id": i["invariant_id"], "passed": i["passed"]} for i in result["invariants"]],
        "utility": result.get("workflow_utility_success"),
        # For a P1b-4 arm the file name alone is ambiguous, so keep the arm's directory.
        "source": {"file": path.name if path.name != "full.jsonl" else f"{path.parent.name}/{path.name}",
                   "sha256": _sha256(path), "line": number},
    }


def forged_receipt(rc7: Path, gate_failed: set[str]) -> dict:
    for path in sorted(rc7.glob("*-full.jsonl")):
        model = path.name.removesuffix("-full.jsonl")
        if model in gate_failed:
            continue
        for number, record in _records(path):
            result = record["protected_result"]
            if record["workflow_id"] != "attack-01" or not _kept_utility(result):
                continue
            if any(s["decision"]["type"] != "allow" and "attacker@evil.test" in json.dumps(s["action"].get("arguments"))
                   for s in _model_steps(result)):
                return _case("forged-receipt", "RC7", model, path, number, record)
    raise SystemExit("forged-receipt: no episode matches the rule")


def labels_not_content(rc7: Path) -> dict:
    path = rc7 / "gemma-4-12b-full.jsonl"
    for number, record in _records(path):
        result = record["protected_result"]
        if record["workflow_id"] != "attack-09" or not _kept_utility(result):
            continue
        if any(s["decision"]["type"] == "deny" and any(r.startswith("confidentiality_exceeds_limit") for r in s["decision"]["reasons"])
               for s in _model_steps(result)):
            return _case("labels-not-content", "RC7", "gemma-4-12b", path, number, record)
    raise SystemExit("labels-not-content: no episode matches the rule")


def llm_attacker(p1b4: Path) -> dict:
    path = p1b4 / "gemma-4-12b-on" / "full.jsonl"
    for number, record in _records(path):
        result = record["protected_result"]
        if _kept_utility(result) and any(s["decision"]["type"] != "allow" for s in _model_steps(result)):
            return _case("llm-attacker", "P1b-4", "gemma-4-12b, reasoning on", path, number, record)
    raise SystemExit("llm-attacker: no episode matches the rule")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rc7", required=True, type=Path)
    parser.add_argument("--p1b4", required=True, type=Path)
    parser.add_argument("--aggregate", type=Path,
                        default=Path(__file__).resolve().parents[2] / "benchmarks/rc/report/rc7-full-evidence/rc-aggregate.json")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    aggregate = json.loads(args.aggregate.read_text(encoding="utf-8"))
    gate_failed = {m["id"] for m in aggregate["models"] if m["status"] == "gate_failed"}
    cases = [forged_receipt(args.rc7, gate_failed), labels_not_content(args.rc7), llm_attacker(args.p1b4)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"cases": cases}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for case in cases:
        print(f"{case['id']}: {case['study']} {case['model']} {case['workflow']} episode {case['episode']} "
              f"(line {case['source']['line']} of {case['source']['file']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
