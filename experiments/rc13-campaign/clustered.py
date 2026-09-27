"""Story-clustered intervals for the RC13 campaign. Exploratory: not in the pre-registration.

    .venv\\Scripts\\python.exe experiments\\rc13-campaign\\clustered.py [--results <dir>]

The registered analysis treats each arm's 240 episodes as independent. They are not: an arm is
20 stories of 12 adaptive episodes, and whether an attack lands depends heavily on the story.
This resamples whole stories (10,000 replicates, seed 13): per arm for its rate, jointly for both
arms of a model (they share the same 20 stories), and models then stories for the pooled mean.
It also reports each arm's design effect, the variance of its story rates over the binomial
variance. Writes results/clustered.json next to this file.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics
import sys

HERE = Path(__file__).resolve().parent
REPLICATES, SEED = 10_000, 13


def per_story(path: Path) -> dict[str, tuple[int, int]]:
    """story -> (episodes with an attack-added security event, evaluable episodes)"""
    out: dict[str, tuple[int, int]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if not record.get("reward_evaluated"):
            continue
        added = bool((record.get("pair_delta") or {}).get("added_security_events"))
        k, n = out.get(record["workflow_id"], (0, 0))
        out[record["workflow_id"]] = (k + added, n + 1)
    return out


def rate(table: dict[str, tuple[int, int]], stories: list[str]) -> float:
    return sum(table[s][0] for s in stories) / sum(table[s][1] for s in stories)


def interval(values: list[float]) -> list[float]:
    values = sorted(values)
    return [values[int(0.025 * len(values))], values[int(0.975 * len(values)) - 1]]


def design_effect(table: dict[str, tuple[int, int]]) -> float | None:
    k = sum(a for a, _ in table.values())
    n = sum(b for _, b in table.values())
    p = k / n
    if p in (0.0, 1.0):
        return None
    per = n / len(table)
    return statistics.pvariance([a / b for a, b in table.values()]) / (p * (1 - p) / per)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=HERE / "results")
    args = parser.parse_args()
    study = json.loads((HERE / "study.json").read_text(encoding="utf-8"))
    rng = random.Random(SEED)

    arms = {arm["id"]: per_story(args.results / arm["id"] / "full.jsonl") for arm in study["arms"]}
    out_arms = {}
    for arm_id, table in arms.items():
        stories = sorted(table)
        boots = [rate(table, [rng.choice(stories) for _ in stories]) for _ in range(REPLICATES)]
        out_arms[arm_id] = {"rate": rate(table, stories), "clustered_ci95": interval(boots),
                            "design_effect": design_effect(table)}

    models = list(dict.fromkeys(arm["model"] for arm in study["arms"]))
    out_models, differences = {}, []
    for model in models:
        reasons, outcomes = arms[f"{model}-reasons"], arms[f"{model}-outcomes"]
        stories = sorted(set(reasons) & set(outcomes))
        d = rate(reasons, stories) - rate(outcomes, stories)
        boots = []
        for _ in range(REPLICATES):
            sample = [rng.choice(stories) for _ in stories]
            boots.append(rate(reasons, sample) - rate(outcomes, sample))
        out_models[model] = {"reasons_minus_outcomes": d, "clustered_ci95": interval(boots)}
        differences.append(d)

    pooled = []
    for _ in range(REPLICATES):
        sample_models = [rng.choice(models) for _ in models]
        acc = []
        for model in sample_models:
            reasons, outcomes = arms[f"{model}-reasons"], arms[f"{model}-outcomes"]
            stories = sorted(set(reasons) & set(outcomes))
            sample = [rng.choice(stories) for _ in stories]
            acc.append(rate(reasons, sample) - rate(outcomes, sample))
        pooled.append(sum(acc) / len(acc))

    effects = [a["design_effect"] for a in out_arms.values() if a["design_effect"] is not None]
    result = {
        "note": "exploratory; not pre-registered",
        "replicates": REPLICATES, "seed": SEED,
        "arms": out_arms,
        "models": out_models,
        "pooled": {"mean": sum(differences) / len(differences), "two_level_ci95": interval(pooled)},
        "design_effect": {"mean": statistics.mean(effects), "min": min(effects), "max": max(effects)},
        "models_whose_clustered_ci_excludes_zero": sum(
            1 for m in out_models.values() if m["clustered_ci95"][0] > 0 or m["clustered_ci95"][1] < 0),
    }
    path = HERE / "results" / "clustered.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for model, m in out_models.items():
        lo, hi = m["clustered_ci95"]
        print(f"{model:24s} {100 * m['reasons_minus_outcomes']:+6.1f}  ({100 * lo:+.1f} to {100 * hi:+.1f})")
    lo, hi = result["pooled"]["two_level_ci95"]
    print(f"pooled {100 * result['pooled']['mean']:+.1f} ({100 * lo:+.1f} to {100 * hi:+.1f}); "
          f"design effect mean {result['design_effect']['mean']:.2f}; "
          f"per-model intervals excluding zero: {result['models_whose_clustered_ci_excludes_zero']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
