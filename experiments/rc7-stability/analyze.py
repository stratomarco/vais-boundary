"""Analysis for the RC7 stability study, exactly as PREREGISTRATION.md fixes it.

Compares runs of the same model episode by episode, matched by story and episode number:
RC7 against Part A (time, engine and files), A against B (repetition), RC7 against C (all but
the engine). Writes results/analysis.json.

    python experiments/rc7-stability/analyze.py --rc7 <evidence>/rc7/rc7 [--results experiments/rc7-stability/results]
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

STUDY_DIR = Path(__file__).resolve().parent
REPLICATES, SEED = 10_000, 7


def load(path: Path) -> dict[tuple[str, int], dict] | None:
    if not path.exists():
        return None
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return {(r["workflow_id"], r["episode"]): r for r in rows}


def actions(result: dict | None) -> list:
    """The agent's proposed actions in one run: tool and argument values, in order."""
    out = []
    for step in (result or {}).get("trace") or []:
        action = step.get("action")
        if action and str(step.get("phase", "")).startswith("agent_turn"):
            out.append([action["tool"], sorted((k, json.dumps(v.get("data"), sort_keys=True))
                                               for k, v in (action.get("arguments") or {}).items())])
    return out


def same_episode(a: dict, b: dict) -> bool:
    return ((a.get("candidate") or {}).get("content_hash") == (b.get("candidate") or {}).get("content_hash")
            and all(actions(a.get(part)) == actions(b.get(part))
                    for part in ("protected_result", "unprotected_result", "control_result")))


def added(r: dict) -> bool:
    return bool((r.get("pair_delta") or {}).get("added_security_events"))


def rate(rows: dict) -> tuple[int, int]:
    evaluable = [r for r in rows.values() if r.get("reward_evaluated")]
    return sum(added(r) for r in evaluable), len(evaluable)


def violations(rows: dict) -> int:
    return sum(1 for r in rows.values() if r.get("reward_evaluated") and r.get("violated_invariants"))


def change_interval(first: dict, second: dict) -> tuple[float, float]:
    """95% interval for (second - first) in attack-added rate, resampling stories, paired by story."""
    stories = sorted({k[0] for k in first})

    def by_story(rows):
        out = {}
        for (story, _), r in rows.items():
            if r.get("reward_evaluated"):
                k, n = out.get(story, (0, 0))
                out[story] = (k + added(r), n + 1)
        return out

    a, b = by_story(first), by_story(second)
    rng = random.Random(SEED)
    diffs = []
    for _ in range(REPLICATES):
        pick = [rng.choice(stories) for _ in stories]
        ka, na = sum(a.get(s, (0, 0))[0] for s in pick), sum(a.get(s, (0, 0))[1] for s in pick)
        kb, nb = sum(b.get(s, (0, 0))[0] for s in pick), sum(b.get(s, (0, 0))[1] for s in pick)
        if na and nb:
            diffs.append(kb / nb - ka / na)
    diffs.sort()
    return diffs[int(0.025 * len(diffs))], diffs[int(0.975 * len(diffs)) - 1]


def compare(first: dict, second: dict) -> dict:
    keys = sorted(set(first) & set(second))
    reproduced = [k for k in keys if same_episode(first[k], second[k])]
    first_divergence = {}
    for story in sorted({k[0] for k in keys}):
        episodes = sorted(e for s, e in keys if s == story)
        first_divergence[story] = next((e for e in episodes if (story, e) not in set(reproduced)), None)
    (ka, na), (kb, nb) = rate(first), rate(second)
    lo, hi = change_interval(first, second)
    return {"matched_episodes": len(keys), "reproduced_exactly": len(reproduced),
            "stories_fully_reproduced": sum(1 for v in first_divergence.values() if v is None),
            "first_divergent_episode": first_divergence,
            "attack_added": {"first": [ka, na], "second": [kb, nb], "change": (kb / nb - ka / na) if na and nb else None,
                             "change_ci95_story_resampled": [lo, hi]},
            "protected_violations": {"first": violations(first), "second": violations(second)}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rc7", required=True, help="the archived RC7 records directory")
    parser.add_argument("--results", default=str(STUDY_DIR / "results"))
    args = parser.parse_args()
    rc7_dir, results = Path(args.rc7), Path(args.results)
    study = json.loads((STUDY_DIR / "study.json").read_text(encoding="utf-8"))
    report: dict = {"registration": study["registration"], "models": {}}
    for arm in study["arms"]:
        rc7 = load(rc7_dir / f"{arm['id']}-full.jsonl")
        parts = {p: load(results / p / arm["id"] / "full.jsonl") for p in "ABC"}
        env = {}
        for p in "ABC":
            e = results / p / arm["id"] / "environment.json"
            if e.exists():
                env[p] = json.loads(e.read_text(encoding="utf-8"))
        entry = {"model_file_changed": any(v["model_file"]["changed_since_rc7"] for v in env.values()),
                 "engines": {p: v["engine"] for p, v in env.items()},
                 "model_sha256": {p: v["model_file"]["sha256"] for p, v in env.items()}}
        for label, first, second in (("rc7_vs_A", rc7, parts["A"]), ("A_vs_B", parts["A"], parts["B"]),
                                     ("rc7_vs_C", rc7, parts["C"])):
            if first and second:
                entry[label] = compare(first, second)
        report["models"][arm["id"]] = entry

    unchanged = {m: e for m, e in report["models"].items() if "rc7_vs_A" in e and not e["model_file_changed"]}
    changes = {m: abs(e["rc7_vs_A"]["attack_added"]["change"]) for m, e in unchanged.items()}
    exact = all(e["rc7_vs_A"]["reproduced_exactly"] == e["rc7_vs_A"]["matched_episodes"] for e in unchanged.values())
    moved = [m for m, e in unchanged.items()
             if not (e["rc7_vs_A"]["attack_added"]["change_ci95_story_resampled"][0] <= 0
                     <= e["rc7_vs_A"]["attack_added"]["change_ci95_story_resampled"][1])]
    report["P1_protected_violations_part_A"] = sum(e["rc7_vs_A"]["protected_violations"]["second"] for e in unchanged.values())
    report["D1_run_to_run_band"] = None if exact else (max(changes.values()) if changes else None)
    report["D1_every_unchanged_model_reproduced_exactly"] = exact if unchanged else None
    report["D2_models_moved_beyond_interval"] = moved
    report["D2_verdict"] = (None if not unchanged else
                            "RC7 per-model rates are one draw; cross-model comparisons get a caveat" if moved
                            else "RC7 per-model rates are stable to within the observed change")
    out = results / "analysis.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(report, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    print("| Model | Comparison | Reproduced exactly | Stories fully reproduced | Attack-added first -> second (change, 95% CI) | Violations |")
    print("|---|---|---|---|---|---|")
    for m, e in report["models"].items():
        for label in ("rc7_vs_A", "A_vs_B", "rc7_vs_C"):
            c = e.get(label)
            if not c:
                continue
            a = c["attack_added"]
            lo, hi = a["change_ci95_story_resampled"]
            print(f"| {m}{' (file changed)' if e['model_file_changed'] else ''} | {label} | {c['reproduced_exactly']}/{c['matched_episodes']} | "
                  f"{c['stories_fully_reproduced']}/20 | {a['first'][0]}/{a['first'][1]} -> {a['second'][0]}/{a['second'][1]} "
                  f"({a['change']:+.1%}, {lo:+.1%} to {hi:+.1%}) | {c['protected_violations']['second']} |")
    print(f"P1 protected violations in part A: {report['P1_protected_violations_part_A']}; D1 band: {report['D1_run_to_run_band']}; "
          f"D2: {report['D2_verdict']} {report['D2_models_moved_beyond_interval']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
