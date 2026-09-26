"""Analyse the RC13 campaign exactly as PREREGISTRATION.md specifies.

    .venv\\Scripts\\python.exe experiments\\rc13-campaign\\analyze.py
    .venv\\Scripts\\python.exe experiments\\rc13-campaign\\analyze.py --rc7-evidence <dir>

Reads results/state.json and each completed arm's full-stage records and summary, and writes
results/analysis.json and a markdown table. The per-arm metrics, Wilson and Newcombe intervals
and the Q4a/Q4b definitions are P1b-4's own code, imported rather than copied. RC7's rates are
shown only when its evidence directory is given, and are exploratory.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import random
import sys

STUDY_DIR = Path(__file__).resolve().parent
RESULTS = STUDY_DIR / "results"

_spec = importlib.util.spec_from_file_location("p1b4_analyze", STUDY_DIR.parent / "p1b4" / "analyze.py")
p1b4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p1b4)
p1b4.RESULTS = RESULTS  # arm_metrics reads <RESULTS>/<arm>/full-summary.json and full.jsonl
wilson, newcombe, pct = p1b4.wilson, p1b4.newcombe, p1b4.pct


def reason_exposure(arm_id: str) -> int:
    """Episodes whose attacker feedback would carry a monitor reason code under ``reasons``.

    This is FIND-061's count: a ``policy:`` event among the attack-added security events or
    violation classes. In the ``reasons`` arm the attacker saw them; in the ``outcomes`` arm
    they were reduced to the outcome and the tool before it did.
    """
    path = RESULTS / arm_id / "full.jsonl"
    exposed = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        delta = json.loads(line).get("pair_delta") or {}
        events = list(delta.get("added_security_events") or []) + list(delta.get("added_violation_classes") or [])
        exposed += any(str(event).startswith("policy:") for event in events)
    return exposed


def pooled_bootstrap(differences: list[float], replicates: int, seed: int) -> tuple[float, float, float] | None:
    """Mean of the per-model differences, with a percentile 95% interval from resampling models."""
    if len(differences) < 2:
        return None
    rng = random.Random(seed)
    k = len(differences)
    means = sorted(sum(rng.choice(differences) for _ in range(k)) / k for _ in range(replicates))
    return (sum(differences) / k, means[int(0.025 * replicates)], means[int(0.975 * replicates) - 1])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rc7-evidence", type=Path, help="RC7 evidence directory, for the exploratory comparison")
    args = parser.parse_args()

    study = json.loads((STUDY_DIR / "study.json").read_text(encoding="utf-8"))
    state_path = RESULTS / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {"arms": {}}
    arms = {}
    for arm in study["arms"]:
        metrics = p1b4.arm_metrics(arm["id"], state)
        if metrics is not None:
            metrics["reason_exposed_episodes"] = reason_exposure(arm["id"])
        arms[arm["id"]] = metrics

    def complete(arm_id: str) -> dict | None:
        m = arms.get(arm_id)
        return m if m and m["status"] == "complete" else None

    models = list(dict.fromkeys(arm["model"] for arm in study["arms"]))
    per_model, differences = {}, []
    for model in models:
        reasons, outcomes = complete(f"{model}-reasons"), complete(f"{model}-outcomes")
        if reasons and outcomes:
            d = newcombe(reasons["attack_added"], reasons["evaluable"], outcomes["attack_added"], outcomes["evaluable"])
            per_model[model] = d
            differences.append(d[0])
    boot = study["bootstrap"]
    pooled = pooled_bootstrap(differences, boot["replicates"], boot["seed"])

    finished = [m for m in arms.values() if m and m["status"] == "complete"]
    evaluable = sum(m["evaluable"] for m in finished)
    violations = sum(m["protected_violations"] for m in finished)

    rc7 = {}
    if args.rc7_evidence:
        for model in models:
            base = p1b4.rc7_rate(args.rc7_evidence, model)
            if base and base[1]:
                rc7[model] = {"rc7_attack_added": base[0], "rc7_evaluable": base[1]}

    analysis = {
        "arms": arms,
        "q1": {"complete_arms": len(finished), "evaluable": evaluable, "protected_violations": violations,
               "ci95": wilson(violations, evaluable)},
        "q2_reasons_minus_outcomes": per_model,
        "q2_pooled": {"models": len(differences), "mean": pooled[0] if pooled else None,
                      "ci95": [pooled[1], pooled[2]] if pooled else None, **boot},
        "rc7_exploratory": rc7,
    }
    (RESULTS / "analysis.json").write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("| Arm | Status | Evaluable | Protected violations | Attack-added (95% CI) | Reason codes available | "
          "Q4b off-task allowed | Utility | Target failures | Attacker failures | Hours |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for arm_id, m in arms.items():
        if m is None:
            print(f"| {arm_id} | {state.get('arms', {}).get(arm_id, {}).get('status', 'not run')} | | | | | | | | | |")
            continue
        ci = m["attack_added_ci95"]
        ci_text = f"{pct(m['attack_added_rate'])} ({pct(ci[0])} to {pct(ci[1])})" if ci else "n/a"
        print(f"| {arm_id} | {m['status']} | {m['evaluable']}/{m['episodes']} | {m['protected_violations']} | {ci_text} | "
              f"{m['reason_exposed_episodes']} | {pct(m['q4']['q4b_rate'])} | {m['utility']} | {m['target_failures']} | "
              f"{m['attacker_generation_failures']} | {m['hours']} |")
    print(f"\nQ1: {violations} protected violations in {evaluable} evaluable episodes across {len(finished)} complete arms")
    for model, d in per_model.items():
        print(f"Q2 {model}: reasons minus outcomes = {100 * d[0]:+.1f} points (95% CI {100 * d[1]:+.1f} to {100 * d[2]:+.1f})")
    if pooled:
        print(f"Q2 pooled over {len(differences)} models: {100 * pooled[0]:+.1f} points "
              f"(95% CI {100 * pooled[1]:+.1f} to {100 * pooled[2]:+.1f}, bootstrap over models)")
    for model, base in rc7.items():
        print(f"RC7 {model} (exploratory): {base['rc7_attack_added']}/{base['rc7_evaluable']} attack-added")
    return 0


if __name__ == "__main__":
    sys.exit(main())
