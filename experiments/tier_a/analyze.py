"""Analyse Tier-A results exactly as pre-registered in PREREGISTRATION.md.

    python -m experiments.tier_a.analyze results/tier_a/v1 --out results/tier_a/v1/summary.md
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def arm_label(r: dict) -> str:
    return f"FILTER[{r['detector']}]" if r["arm"] == "FILTER" else r["arm"]


def load(results_dir: Path) -> list[dict]:
    rows = []
    for f in sorted(results_dir.glob("*.jsonl")):
        rows += [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows


def analyse(rows: list[dict]) -> str:
    out = []
    by_run: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_run[r["agent"]].append(r)

    for agent, rs in sorted(by_run.items()):
        out.append(f"## Agent `{agent}`\n")
        off = {r["workflow"]: r for r in rs if r["arm"] == "OFF"}
        attacks = {r["workflow"]: r.get("family") for r in rs if r["kind"] == "attack"}
        validated = {w for w, r in off.items() if r["kind"] == "attack" and r["effect_achieved"]}

        out.append("| Family | Generated | Validated under OFF | Discard rate |\n|---|---|---|---|")
        for fam in sorted({f for f in attacks.values() if f}):
            gen = [w for w, f in attacks.items() if f == fam]
            val = [w for w in gen if w in validated]
            out.append(f"| {fam} | {len(gen)} | {len(val)} | {1 - len(val) / max(1, len(gen)):.0%} |")
        out.append("")

        arms = sorted({arm_label(r) for r in rs})
        out.append("| Arm | Family A caught | Family B caught (primary) | Benign OK | Paired vs OFF (S→F / F→S) | Benign content dropped |")
        out.append("|---|---|---|---|---|---|")
        for arm in arms:
            ar = [r for r in rs if arm_label(r) == arm]
            cells = []
            for fam in ("A", "B"):
                v = [r for r in ar if r["kind"] == "attack" and r.get("family") == fam and r["workflow"] in validated]
                k = sum(1 for r in v if not r["effect_achieved"])
                lo, hi = wilson(k, len(v))
                cells.append(f"{k}/{len(v)} ({k / len(v):.0%}, CI {lo:.0%}–{hi:.0%})" if v else "–")
            ben = [r for r in ar if r["kind"] == "benign"]
            ok = sum(1 for r in ben if r["task_ok"])
            sf = sum(1 for r in ben if off.get(r["workflow"], {}).get("task_ok") and not r["task_ok"])
            fs = sum(1 for r in ben if not off.get(r["workflow"], {}).get("task_ok") and r["task_ok"])
            seen = sum(len(r.get("retrieved", [])) for r in ben)
            dropped = sum(len(r.get("dropped", [])) for r in ben)
            drop_cell = f"{dropped}/{seen} ({dropped / seen:.0%})" if seen else "–"
            out.append(f"| {arm} | {cells[0]} | {cells[1]} | {ok}/{len(ben)} | {sf} / {fs} | {drop_cell} |")
        out.append("")

        fails = defaultdict(list)
        for r in rs:
            if r["kind"] == "benign" and not r["task_ok"]:
                fails[arm_label(r)].append(r["workflow"])
        out.append("Benign failures by arm:\n")
        for arm in arms:
            out.append(f"- {arm}: {', '.join(sorted(fails[arm])) or 'none'}")
        out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    text = analyse(load(args.results_dir))
    print(text)
    if args.out:
        args.out.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
