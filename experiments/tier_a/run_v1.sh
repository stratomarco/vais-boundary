#!/usr/bin/env bash
# Tier-A v1 runs exactly as pre-registered. Usage: run_v1.sh <temperature> <seed> <outdir>
set -euo pipefail
T="$1"; S="$2"; OUT="$3"; V=experiments/tier_a/variants/gen-v1.jsonl
PY=./.venv/Scripts/python.exe
mkdir -p "$OUT"
$PY -m experiments.tier_a.run --variants $V --temperature "$T" --seed "$S" --arms OFF,APP_AUTHZ,VAIS,VAIS_OP --detector keyword --out "$OUT/core.jsonl"
$PY -m experiments.tier_a.run --variants $V --temperature "$T" --seed "$S" --arms FILTER --detector keyword --out "$OUT/filter-keyword.jsonl"
$PY -m experiments.tier_a.run --variants $V --temperature "$T" --seed "$S" --arms FILTER --detector classifier --out "$OUT/filter-classifier.jsonl"
for J in phi-4-mini-instruct granite-4.1-8b qwen2.5-7b-instruct; do
  $PY -m experiments.tier_a.run --variants $V --temperature "$T" --seed "$S" --arms FILTER --detector llm_judge --judge-model $J --out "$OUT/filter-judge-$J.jsonl"
done
$PY -m experiments.tier_a.analyze "$OUT" --out "$OUT/summary.md"
