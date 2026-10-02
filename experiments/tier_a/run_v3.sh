#!/usr/bin/env bash
# Tier-A v3 runs exactly as pre-registered. Usage: run_v3.sh <model> <temperature> <seed> <outdir>
# Run from the repository root. PY defaults to the repository's virtual environment; set it to use another.
set -euo pipefail
M="$1"; T="$2"; S="$3"; OUT="$4"
V=experiments/tier_a/variants/gen-v3.jsonl
CORPUS=experiments/tier_a/variants/benign-docs-v3.jsonl
PY="${PY:-./.venv/Scripts/python.exe}"
export PYTHONPATH="src;."
COMMON=(--variants $V --model "$M" --temperature "$T" --seed "$S" --benign-suite v2)
JUDGES=(phi-4-mini-instruct granite-4.1-8b qwen2.5-7b-instruct)
mkdir -p "$OUT/corpus"
$PY -m experiments.tier_a.run "${COMMON[@]}" --arms OFF,APP_AUTHZ,VAIS,VAIS_OP,VAIS_RESOLVE --detector keyword --out "$OUT/core.jsonl"
$PY -m experiments.tier_a.run "${COMMON[@]}" --arms FILTER --detector keyword --out "$OUT/filter-keyword.jsonl"
$PY -m experiments.tier_a.run "${COMMON[@]}" --arms FILTER --detector classifier --out "$OUT/filter-classifier.jsonl"
for J in "${JUDGES[@]}"; do
  $PY -m experiments.tier_a.run "${COMMON[@]}" --arms FILTER --detector llm_judge --judge-model $J --out "$OUT/filter-judge-$J.jsonl"
done
# The cost axis: what each detector drops from the frozen benign corpus. No agent runs here.
$PY -m experiments.tier_a.detector_cost --corpus $CORPUS --detector keyword --out "$OUT/corpus/keyword.jsonl"
$PY -m experiments.tier_a.detector_cost --corpus $CORPUS --detector classifier --out "$OUT/corpus/classifier.jsonl"
for J in "${JUDGES[@]}"; do
  $PY -m experiments.tier_a.detector_cost --corpus $CORPUS --detector llm_judge --judge-model $J --out "$OUT/corpus/judge-$J.jsonl"
done
$PY -m experiments.tier_a.analyze "$OUT" --primary C --v3 --out "$OUT/summary.md"
