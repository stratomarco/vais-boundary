"""Summarise the P1b-2 frontier pilot: one Claude model through the four RC stages.

Reads results/api/<prefix>-<stage>.jsonl and -summary.json (gitignored) and writes
experiments/p1b2-pilot/analysis.json. Costs use Anthropic's list prices at the time of
the run and are estimates; the account's own usage page is authoritative.

Zero-event rates get two 95% upper bounds: a Wilson bound treating episodes as
independent, and the same bound on an effective sample size divided by the design effect
RC13 measured for this reference application (FIND-065), because episodes of one story
are correlated.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
from pathlib import Path

STAGES = ("preflight", "qualification", "screening", "full")
PRICES = {"claude-sonnet-5-5": (2.00, 10.00), "claude-opus-5-5": (4.00, 20.00)}  # USD per 1M input/output tokens
RC13_DESIGN_EFFECT = 5.7


def wilson_upper(successes: int, n: float, z: float = 1.96) -> float | None:
    if n <= 0:
        return None
    p = successes / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + margin) / (1 + z * z / n))


def rate(events: int, n: int) -> dict:
    return {
        "events": events,
        "n": n,
        "upper95_independent": wilson_upper(events, n),
        # Effective sample: events and trials both divided by the design effect.
        "upper95_story_clustered": wilson_upper(events / RC13_DESIGN_EFFECT, n / RC13_DESIGN_EFFECT),
    }


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)]


def stage_summary(root: Path, prefix: str, stage: str) -> dict | None:
    episodes_path = root / f"{prefix}-{stage}.jsonl"
    if not episodes_path.exists():
        return None
    episodes = [json.loads(line) for line in episodes_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    stories = sorted({e["workflow_id"] for e in episodes})
    served: set[str] = set()
    statuses: collections.Counter = collections.Counter()
    finish: collections.Counter = collections.Counter()
    decisions: collections.Counter = collections.Counter()
    tokens_in = tokens_out = reasoning_chars = 0
    latencies: list[float] = []
    seen_generations: set[int] = set()
    violations = added = objective = utility = evaluable = control_overreach = 0
    controls_seen: set[str] = set()

    def count_generations(result: dict) -> None:
        nonlocal tokens_in, tokens_out, reasoning_chars
        for g in result["target_generations"]:
            statuses[g["status"]] += 1
            finish[g["finish_reason"]] += 1
            if g["cache_hit"]:
                continue
            tokens_in += g["input_tokens"] or 0
            tokens_out += g["output_tokens"] or 0
            reasoning_chars += g["reasoning_chars"] or 0
            if g["latency_ms"] is not None:
                latencies.append(g["latency_ms"])

    for episode in episodes:
        protected = episode["protected_result"]
        control = episode["control_result"]
        if control is not None and episode["workflow_id"] not in controls_seen:
            controls_seen.add(episode["workflow_id"])
            count_generations(control)
            served.update(filter(None, control["target_metadata"].get("served_models", "").split(",")))
            if control["security_events"]:
                control_overreach += 1
        if protected is None:
            continue
        count_generations(protected)
        served.update(filter(None, protected["target_metadata"].get("served_models", "").split(",")))
        if episode["reward_evaluated"]:
            evaluable += 1
        violations += bool(episode["violated_invariants"])
        added += bool((episode["pair_delta"] or {}).get("added_security_events"))
        objective += bool(protected["attack_objective_success"])
        utility += bool(protected["workflow_utility_success"])
        for step in protected["trace"]:
            if step["action"] and step["phase"].startswith("agent_turn") and step["decision"]:
                kind = step["decision"]["type"]
                if kind != "allow":
                    reason = (step["decision"]["reasons"] or [kind])[0].split(":")[0]
                    decisions[f"{kind}:{reason}"] += 1

    models = sorted(served)
    price = PRICES.get(models[0]) if len(models) == 1 else None
    cost = None if price is None else round(tokens_in * price[0] / 1e6 + tokens_out * price[1] / 1e6, 2)
    return {
        "episodes": len(episodes),
        "evaluable_episodes": evaluable,
        "stories": len(stories),
        "served_models": models,
        "protected_violations": rate(violations, evaluable),
        "attack_added_security_events": rate(added, evaluable),
        "attack_objective_successes": rate(objective, evaluable),
        "protected_utility": {"successes": utility, "n": len(episodes)},
        "matched_control_overreach": {"controls_with_security_events": control_overreach, "controls": len(controls_seen)},
        "non_allow_decisions_in_protected_runs": dict(decisions),
        "generation_statuses": dict(statuses),
        "finish_reasons": dict(finish),
        "refusals": finish.get("refusal", 0),
        "reasoning_chars_observed": reasoning_chars,
        "billed_tokens": {"input": tokens_in, "output": tokens_out},
        "estimated_cost_usd": cost,
        "latency_ms": {"p50": percentile(latencies, 0.5), "p95": percentile(latencies, 0.95), "calls": len(latencies)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="results/api")
    parser.add_argument("--prefix", default="sonnet-5-5")
    parser.add_argument("--output", default="experiments/p1b2-pilot/analysis.json")
    args = parser.parse_args()
    root = Path(args.results)
    stages = {stage: stage_summary(root, args.prefix, stage) for stage in STAGES}
    present = {k: v for k, v in stages.items() if v is not None}
    total_cost = sum(v["estimated_cost_usd"] or 0 for v in present.values())
    report = {
        "prefix": args.prefix,
        "rc13_design_effect_used": RC13_DESIGN_EFFECT,
        "stages": stages,
        "estimated_total_cost_usd": round(total_cost, 2),
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    for stage, data in present.items():
        v = data["protected_violations"]
        a = data["attack_added_security_events"]
        print(f"{stage:13} episodes={data['episodes']:3} violations={v['events']}/{v['n']} "
              f"(95% upper {v['upper95_independent']:.3f}, clustered {v['upper95_story_clustered']:.3f}) "
              f"added={a['events']} utility={data['protected_utility']['successes']}/{data['protected_utility']['n']} "
              f"non_allow={sum(data['non_allow_decisions_in_protected_runs'].values())} refusals={data['refusals']} "
              f"cost=${data['estimated_cost_usd']}")
    print(f"estimated total ${report['estimated_total_cost_usd']}")


if __name__ == "__main__":
    main()
