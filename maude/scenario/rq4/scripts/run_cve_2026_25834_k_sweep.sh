#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
RUNNER="$REPO_ROOT/maude/scenario/rq4/scripts/run_strategy_guided_counts.py"
STATE_DIR="$REPO_ROOT/maude/scenario/rq4/state"

CASE="${CASE:-cve-2026-25834}"
SOLUTION_CAP="${SOLUTION_CAP:-1000000}"
MAX_PRE="${MAX_PRE:-50}"
MAX_MID="${MAX_MID:-50}"
MAX_POST="${MAX_POST:-50}"
ZERO_STREAK="${ZERO_STREAK:-2}"
TIMEOUT="${TIMEOUT:-7200}"
PROBE_MODE="${PROBE_MODE:-batch}"
K_VALUES="${K_VALUES:-10 20 30 40 50 60 70 80 90 100}"
FULL_SAMPLE_METHOD="${FULL_SAMPLE_METHOD:-random}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10}"
FULL_SOURCES="${FULL_SOURCES:-5246-core 8446-core hrr}"

MAUDE_ARGS=()
if [[ -n "${MAUDE_BIN:-}" ]]; then
  MAUDE_ARGS=(--maude-bin "$MAUDE_BIN")
fi

mkdir -p "$STATE_DIR"

run_experiment() {
  local variant="$1"
  local mode="$2"
  local k="${3:-}"
  local seed="${4:-}"
  local label
  local log
  local args=(
    python3 "$RUNNER"
    "${MAUDE_ARGS[@]}"
    --case "$CASE"
    --variant "$variant"
    --mode "$mode"
    --count-method binary
    --probe-mode "$PROBE_MODE"
    --solution-cap "$SOLUTION_CAP"
    --max-pre "$MAX_PRE"
    --max-mid "$MAX_MID"
    --max-post "$MAX_POST"
    --zero-streak "$ZERO_STREAK"
    --timeout "$TIMEOUT"
    --summary-scope current-run
    --full-sources "$FULL_SOURCES"
  )

  if [[ "$variant" == "full" ]]; then
    args+=(--full-limit "$k")
    if [[ "$FULL_SAMPLE_METHOD" == "random" ]]; then
      args+=(--full-sample-method random --full-seed "$seed")
      label="$CASE.full-$k.seed-$seed.$mode"
    else
      args+=(--full-sample-method prefix)
      label="$CASE.full-$k.$mode"
    fi
  else
    label="$CASE.scoped.$mode"
  fi

  log="$STATE_DIR/$label.log"
  echo "[rq4-sweep] start $label"
  echo "[rq4-sweep] log $log"
  "${args[@]}" 2>&1 | tee "$log"
  echo "[rq4-sweep] done $label"
}

# Scoped is independent of k, so run it once per mode as the baseline.
run_experiment scoped scan
run_experiment scoped time

read -r -a K_LIST <<< "$K_VALUES"
read -r -a SEED_LIST <<< "$SEEDS"
for k in "${K_LIST[@]}"; do
  if [[ "$FULL_SAMPLE_METHOD" == "random" ]]; then
    for seed in "${SEED_LIST[@]}"; do
      run_experiment full scan "$k" "$seed"
      run_experiment full time "$k" "$seed"
    done
  else
    run_experiment full scan "$k"
    run_experiment full time "$k"
  fi
done
