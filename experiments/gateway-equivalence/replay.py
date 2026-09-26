r"""Replay recorded library-path traces through the gateway; see vais.gateway_replay.

    .venv\Scripts\python.exe experiments\gateway-equivalence\replay.py <label> <full.jsonl>... --out <summary.json>

Every protected trace in the given adaptive-episode files (the attacked run and its matched
control) is replayed; the summary counts identical traces, stricter and looser decisions, and
argument labels. No model is involved, so no GPU is needed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from vais.gateway_replay import load_records, replay_records, summarize


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("label")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    per_file, everything = {}, []
    for path in args.files:
        comparisons = [c for *_, c in replay_records(load_records(path))]
        everything += comparisons
        per_file[path.parent.name if path.name == "full.jsonl" else path.stem] = summarize(comparisons)
    summary = {"label": args.label, "files": len(args.files), "overall": summarize(everything), "by_file": per_file,
               "seconds": round(time.monotonic() - started, 1)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    overall = summary["overall"]
    print(f"{args.label}: {overall['traces']} traces, {overall['traces_identical']} identical, "
          f"decisions {overall['decisions']}, labels {overall['argument_labels']}, {summary['seconds']} s")
    for d in overall["divergences"]:
        print(f"  {d['steps']:5d}  {d['verdict']}: {d['tool']} {d['library']} -> {d['gateway']} (labels changed: {d['labels_changed'] or 'none'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
