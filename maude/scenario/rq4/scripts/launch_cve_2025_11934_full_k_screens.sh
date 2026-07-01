#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
STATE_DIR="$REPO_ROOT/maude/scenario/rq4/state"

mkdir -p "$STATE_DIR"

for k in 100 200 300 400 500 600 700 800 900 1000; do
  session="rq4-11934-full-${k}-seed-1"
  log="$STATE_DIR/cve-2025-11934.full-${k}.seed-1.stdout.log"

  echo "[rq4-screen] starting $session"
  echo "[rq4-screen] log: $log"

  screen -dmS "$session" bash -lc "
    cd '$REPO_ROOT'
    python3 maude/scenario/rq4/scripts/run_strategy_guided_counts.py \
      --case cve-2025-11934 \
      --maude-bin /home/jaehun/maude/maude-3.4/maude.linux64 \
      --variant full \
      --mode scan \
      --count-method binary \
      --probe-mode batch \
      --solution-cap 1000000 \
      --max-pre 20 \
      --max-mid 10 \
      --max-post 20 \
      --full-limit $k \
      --full-sample-method random \
      --full-seed 1 \
      --timeout 43200 \
      > '$log' 2>&1
    echo '[rq4-screen] finished k=$k' >> '$log'
    exec bash
  "
done

screen -ls
