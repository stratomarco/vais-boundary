#!/usr/bin/env bash
# Tier-A v2 runs exactly as pre-registered. Usage: run_v2.sh <model> <temperature> <seed> <outdir>
set -euo pipefail
M="$1"; T="$2"; S="$3"; OUT="$4"; V=experiments/tier_a/variants/gen-v2.jsonl
PY=./.venv/Scripts/python.exe
COMMON=(--variants $V --model "$M" --temperature "$T" --seed "$S" --benign-suite v2)
mkdir -p "$OUT"
$PY -m experiments.tier_a.run "${COMMON[@]}" --arms OFF,APP_AUTHZ,VAIS,VAIS_OP,VAIS_RESOLVE --detector keyword --out "$OUT/core.jsonl"
$PY -m experiments.tier_a.run "${COMMON[@]}" --arms FILTER --detector keyword --out "$OUT/filter-keyword.jsonl"
$PY -m experiments.tier_a.run "${COMMON[@]}" --arms FILTER --detector classifier --out "$OUT/filter-classifier.jsonl"
for J in phi-4-mini-instruct granite-4.1-8b qwen2.5-7b-instruct; do
  $PY -m experiments.tier_a.run "${COMMON[@]}" --arms FILTER --detector llm_judge --judge-model $J --out "$OUT/filter-judge-$J.jsonl"
done
$PY -m experiments.tier_a.analyze "$OUT" --primary D --out "$OUT/summary.md"
