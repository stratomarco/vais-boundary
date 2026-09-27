"""Story-clustered intervals for P1b-4, added after FIND-065. Not in the pre-registration.

    .venv\\Scripts\\python.exe experiments\\p1b4\\clustered.py [--results <dir>] [--rc7-evidence <dir>]

Each arm's 240 episodes are 20 stories of 12 adaptive episodes, and the registered Wilson and
Newcombe intervals treat them as independent. This resamples whole stories with the RC13
campaign's code (experiments/rc13-campaign/clustered.py): per arm for its attack-added rate, and
jointly for the reasoning-off and reasoning-on arms of a model, which share the same stories, and,
given RC7's evidence directory, for each reasoning-off arm against RC7's record of the same model
(the exploratory Q3, whose stories are the same 20). Writes results/clustered.json.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import random
import sys

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("rc13_clustered", HERE.parent / "rc13-campaign" / "clustered.py")
rc13 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc13)

# (model, reasoning off arm, reasoning on arm); the follow-up arm stands in for the gate-failed one.
PAIRS = [("gemma-4-12b", "gemma-4-12b-off", "gemma-4-12b-on"),
         ("qwen3.5-9b", "qwen3.5-9b-off", "qwen3.5-9b-on-r2"),
         ("qwen3-0.6b", "qwen3-0.6b-off", "qwen3-0.6b-on")]
ARMS = ["gemma-4-12b-off", "gemma-4-12b-on", "qwen3.5-9b-off", "qwen3.5-9b-on-r2",
        "smollm3-3b-off", "qwen3-0.6b-off", "qwen3-0.6b-on"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=HERE / "results")
    parser.add_argument("--rc7-evidence", type=Path)
    args = parser.parse_args()
    rng = random.Random(rc13.SEED)
    tables = {arm: rc13.per_story(args.results / arm / "full.jsonl") for arm in ARMS}

    arms = {}
    for arm, table in tables.items():
        stories = sorted(table)
        boots = [rc13.rate(table, [rng.choice(stories) for _ in stories]) for _ in range(rc13.REPLICATES)]
        arms[arm] = {"rate": rc13.rate(table, stories), "clustered_ci95": rc13.interval(boots),
                     "design_effect": rc13.design_effect(table)}

    pairs = {}
    for model, off, on in PAIRS:
        stories = sorted(set(tables[off]) & set(tables[on]))
        d = rc13.rate(tables[on], stories) - rc13.rate(tables[off], stories)
        boots = []
        for _ in range(rc13.REPLICATES):
            sample = [rng.choice(stories) for _ in stories]
            boots.append(rc13.rate(tables[on], sample) - rc13.rate(tables[off], sample))
        pairs[model] = {"on_minus_off": d, "clustered_ci95": rc13.interval(boots)}

    versus_rc7 = {}
    if args.rc7_evidence:
        for model, off in (("gemma-4-12b", "gemma-4-12b-off"), ("qwen3.5-9b", "qwen3.5-9b-off"),
                           ("smollm3-3b", "smollm3-3b-off"), ("qwen3-0.6b", "qwen3-0.6b-off")):
            base = rc13.per_story(args.rc7_evidence / f"{model}-full.jsonl")
            stories = sorted(set(tables[off]) & set(base))
            d = rc13.rate(tables[off], stories) - rc13.rate(base, stories)
            boots = []
            for _ in range(rc13.REPLICATES):
                sample = [rng.choice(stories) for _ in stories]
                boots.append(rc13.rate(tables[off], sample) - rc13.rate(base, sample))
            versus_rc7[model] = {"off_minus_rc7": d, "clustered_ci95": rc13.interval(boots)}

    result = {"note": "added after FIND-065; not pre-registered", "replicates": rc13.REPLICATES, "seed": rc13.SEED,
              "arms": arms, "on_minus_off": pairs, "off_minus_rc7": versus_rc7}
    path = HERE / "results" / "clustered.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for arm, a in arms.items():
        lo, hi = a["clustered_ci95"]
        print(f"{arm:20s} {100 * a['rate']:5.1f}%  ({100 * lo:.1f}% to {100 * hi:.1f}%)  design effect {a['design_effect']:.1f}")
    for model, p in pairs.items():
        lo, hi = p["clustered_ci95"]
        print(f"{model:20s} on minus off {100 * p['on_minus_off']:+.1f} ({100 * lo:+.1f} to {100 * hi:+.1f})")
    for model, v in versus_rc7.items():
        lo, hi = v["clustered_ci95"]
        print(f"{model:20s} off minus RC7 {100 * v['off_minus_rc7']:+.1f} ({100 * lo:+.1f} to {100 * hi:+.1f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
