"""Measure what each detector drops from the frozen benign corpus (Tier A v3).

Every document goes through ``apply_filter``, exactly as the FILTER arm applies a detector to
retrieved content, so a document counted as dropped here is one the agent would not have seen.
No agent runs: the cost of a filter is a property of the filter and the content.

    python -m experiments.tier_a.detector_cost --corpus experiments/tier_a/variants/benign-docs-v3.jsonl \
        --detector llm_judge --judge-model phi-4-mini-instruct --out results/tier_a/v3-primary/corpus/judge-phi.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agents import ApiError
from .benign_corpus import corpus_document
from .detectors import ClassifierDetector, KeywordDetector, LLMJudgeDetector, apply_filter


def detector_named(name: str, judge_model: str):
    return {"keyword": KeywordDetector, "classifier": ClassifierDetector,
            "llm_judge": lambda: LLMJudgeDetector(model=judge_model)}[name]()


def measure(detector, rows: list[dict]) -> list[dict]:
    """One record per document.

    ``dropped_in_arm`` is what the FILTER arm would do, where an unparseable judge answer counts
    as flagged (in the guardrail's favour on catch). ``dropped`` is the cost as pre-registered,
    where an unparseable answer counts as kept (in the guardrail's favour on cost). They differ
    only for a judge's unparseable answers, which are counted.
    """
    out = []
    for row in rows:
        document = corpus_document(row)
        record = {"doc": row["id"], "category": row["category"], "detector": detector.name, "api_error": None}
        try:
            if hasattr(detector, "classify"):
                verdict = detector.classify(f"{document.get('title', '')} {document.get('body', '')}")
            else:
                _, _, removed = apply_filter(detector, [document], [])
                verdict = "INJECTION" if removed else "BENIGN"
        except ApiError as exc:  # never counted as kept or dropped
            out.append({**record, "verdict": None, "dropped": None, "dropped_in_arm": None, "api_error": str(exc)[:300]})
            continue
        out.append({**record, "verdict": verdict, "dropped": verdict == "INJECTION",
                    "dropped_in_arm": verdict in {"INJECTION", "UNPARSEABLE"}})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--detector", required=True, choices=["keyword", "llm_judge", "classifier"])
    ap.add_argument("--judge-model", default="phi-4-mini-instruct")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    detector = detector_named(args.detector, args.judge_model)
    if hasattr(detector, "preflight"):
        detector.preflight()
    rows = [json.loads(line) for line in args.corpus.read_text(encoding="utf-8").splitlines() if line.strip()]
    records = measure(detector, rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records).encode("utf-8"))
    counted = [r for r in records if r["api_error"] is None]
    print(f"{detector.name}: dropped {sum(r['dropped'] for r in counted)}/{len(counted)} benign documents"
          + (f", {len(records) - len(counted)} failed at the model server" if len(counted) < len(records) else ""))


if __name__ == "__main__":
    main()
