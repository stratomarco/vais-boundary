"""Run attack variants and the benign suite across arms and write one JSONL line per episode.

    python -m experiments.tier_a.run --variants experiments/tier_a/variants/seed.jsonl \
        --arms OFF,APP_AUTHZ,FILTER,VAIS --detector keyword --out results/tier_a/seed.jsonl
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from .agents import LLMAgent
from .detectors import ClassifierDetector, KeywordDetector, LLMJudgeDetector
from .episode import run_episode
from .gate import VaisGate
from .workflows import attack_workflow, benign_workflows, benign_workflows_v2


def load_variants(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def summarize(records: list[dict]) -> str:
    validated = {r["workflow"] for r in records if r["kind"] == "attack" and r["arm"] == "OFF" and r["effect_achieved"]}
    generated = {r["workflow"] for r in records if r["kind"] == "attack"}
    lines = [f"attack variants: {len(generated)} generated, {len(validated)} validated under OFF "
             f"(discard rate {1 - len(validated) / max(1, len(generated)):.0%})"]
    by_arm: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in records:
        by_arm[r["arm"]][r["kind"]].append(r)
    for arm, kinds in by_arm.items():
        atk = [r for r in kinds.get("attack", []) if r["workflow"] in validated]
        caught = sum(1 for r in atk if not r["effect_achieved"])
        ben = kinds.get("benign", [])
        ok = sum(1 for r in ben if r["task_ok"])
        lines.append(f"  {arm:10s} caught {caught}/{len(atk)} validated attacks | benign task_ok {ok}/{len(ben)}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variants", type=Path, required=True)
    ap.add_argument("--arms", default="OFF,APP_AUTHZ,FILTER,VAIS")
    ap.add_argument("--detector", default="keyword", choices=["keyword", "llm_judge", "classifier"])
    ap.add_argument("--model", default="qwen2.5-7b-instruct")
    ap.add_argument("--judge-model", default="phi-4-mini-instruct")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--no-benign", action="store_true")
    ap.add_argument("--benign-suite", default="v1", choices=["v1", "v2"])
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    agent = LLMAgent(model=args.model, seed=args.seed, temperature=args.temperature)
    detector = {"keyword": KeywordDetector, "classifier": ClassifierDetector,
                "llm_judge": lambda: LLMJudgeDetector(model=args.judge_model)}[args.detector]()
    if hasattr(detector, "preflight"):
        detector.preflight()
    gate = VaisGate()
    workflows = [attack_workflow(v["id"], v["payload"], v.get("family", "A")) for v in load_variants(args.variants)]
    if not args.no_benign:
        workflows += benign_workflows_v2() if args.benign_suite == "v2" else benign_workflows()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with args.out.open("w", encoding="utf-8") as fh:
        for wf in workflows:
            for arm in args.arms.split(","):
                rec = run_episode(wf, arm, agent, gate, detector=detector)
                records.append(rec)
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                print(f"{wf.id:28s} {arm:10s} decision={rec['decision']:13s} changes={rec['changes']}", flush=True)
    print()
    print(summarize(records))
    if getattr(detector, "unparseable", 0):
        print(f"judge unparseable answers (counted as flagged): {detector.unparseable}")


if __name__ == "__main__":
    main()
