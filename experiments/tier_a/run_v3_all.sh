#!/usr/bin/env bash
# Every Tier-A v3 run in PREREGISTRATION-v3.md, one after another, for an unattended night.
# Only orchestration: each run is run_v3.sh with its registered configuration. A run whose
# summary exists is skipped, so the script can be started again after an interruption; a run
# that fails is logged and the next one starts. Run from the repository root.
set -uo pipefail
export PY="${PY:-./.venv/Scripts/python.exe}"
E=experiments/tier_a/evidence
run() {  # name model temperature seed
  local out="$E/v3-$1"
  if [ -f "$out/summary.md" ]; then echo "[$(date -u +%FT%TZ)] $1: already complete, skipping"; return; fi
  mkdir -p "$out"
  echo "[$(date -u +%FT%TZ)] $1: start ($2, t=$3, seed=$4)"
  if bash experiments/tier_a/run_v3.sh "$2" "$3" "$4" "$out" > "$out/run.log" 2>&1; then
    echo "[$(date -u +%FT%TZ)] $1: complete"
  else
    echo "[$(date -u +%FT%TZ)] $1: FAILED, see $out/run.log"
  fi
}
run primary   qwen2.5-7b-instruct 0.0 0
run phi4      phi-4               0.0 0
run robust-s1 qwen2.5-7b-instruct 0.7 1
run robust-s2 qwen2.5-7b-instruct 0.7 2
echo "[$(date -u +%FT%TZ)] all v3 runs finished"
