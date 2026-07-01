#!/usr/bin/env python3
"""Summarize RQ4 random full-k sweep logs.

The expected full log names are:
  cve-....full-K.seed-S.scan.log
  cve-....full-K.seed-S.time.log

Scoped baseline logs are:
  cve-....scoped.scan.log
  cve-....scoped.time.log
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
from pathlib import Path


SCRIPT = Path(__file__).resolve()
RQ4_DIR = SCRIPT.parents[1]
STATE_DIR = RQ4_DIR / "state"

FULL_RE = re.compile(r"^(cve-\d{4}-\d+)\.full-(\d+)\.seed-(\d+)\.(scan|time)\.log$")
SCOPED_RE = re.compile(r"^(cve-\d{4}-\d+)\.scoped\.(scan|time)\.log$")


def load_summary(path: Path) -> dict | None:
    text = path.read_text(errors="replace")
    starts = [match.start() for match in re.finditer(r"(?m)^\{", text)]
    for start in reversed(starts):
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            continue
    return None


def mean(values: list[int]) -> float | None:
    return None if not values else statistics.mean(values)


def stdev(values: list[int]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return statistics.stdev(values)


def fmt(value: float | int | None) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def summarize(state_dir: Path, case_filter: str | None) -> list[dict]:
    full: dict[tuple[str, int, int], dict[str, int]] = {}
    scoped: dict[str, dict[str, int]] = {}

    for path in sorted(state_dir.glob("*.log")):
        full_match = FULL_RE.match(path.name)
        scoped_match = SCOPED_RE.match(path.name)
        if not full_match and not scoped_match:
            continue

        summary = load_summary(path)
        if summary is None:
            continue

        if full_match:
            cve, k_text, seed_text, mode = full_match.groups()
            if case_filter and cve != case_filter:
                continue
            k = int(k_text)
            seed = int(seed_text)
            variant = f"full-{k}-seed-{seed}"
            data = summary.get(cve, {}).get(variant)
            if data is None:
                continue
            row = full.setdefault((cve, k, seed), {})
            if mode == "scan":
                row["state"] = int(data.get("cumulative_state_estimate") or 0)
            else:
                row["time_ms"] = int(data.get("time_elapsed_ms") or 0)
            continue

        assert scoped_match is not None
        cve, mode = scoped_match.groups()
        if case_filter and cve != case_filter:
            continue
        data = summary.get(cve, {}).get("scoped")
        if data is None:
            continue
        row = scoped.setdefault(cve, {})
        if mode == "scan":
            row["state"] = int(data.get("cumulative_state_estimate") or 0)
        else:
            row["time_ms"] = int(data.get("time_elapsed_ms") or 0)

    keys = sorted({(cve, k) for cve, k, _ in full})
    rows: list[dict] = []
    for cve, k in keys:
        seed_rows = [values for (row_cve, row_k, _), values in full.items() if row_cve == cve and row_k == k]
        state_values = [values["state"] for values in seed_rows if "state" in values]
        time_values = [values["time_ms"] for values in seed_rows if "time_ms" in values]
        scoped_row = scoped.get(cve, {})
        rows.append(
            {
                "cve": cve,
                "k": k,
                "n_state": len(state_values),
                "full_state_mean": mean(state_values),
                "full_state_stdev": stdev(state_values),
                "n_time": len(time_values),
                "full_time_mean_ms": mean(time_values),
                "full_time_stdev_ms": stdev(time_values),
                "scoped_state": scoped_row.get("state"),
                "scoped_time_ms": scoped_row.get("time_ms"),
            }
        )
    return rows


def write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "cve",
        "k",
        "n_state",
        "full_state_mean",
        "full_state_stdev",
        "n_time",
        "full_time_mean_ms",
        "full_time_stdev_ms",
        "scoped_state",
        "scoped_time_ms",
    ]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def print_markdown(rows: list[dict]) -> None:
    print(
        "| cve | k | n(state) | full state mean | full state stdev | "
        "n(time) | full time mean(ms) | full time stdev(ms) | scoped state | scoped time(ms) |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for row in rows:
        print(
            f"| {row['cve']} | {row['k']} | {row['n_state']} | "
            f"{fmt(row['full_state_mean'])} | {fmt(row['full_state_stdev'])} | "
            f"{row['n_time']} | {fmt(row['full_time_mean_ms'])} | "
            f"{fmt(row['full_time_stdev_ms'])} | {fmt(row['scoped_state'])} | "
            f"{fmt(row['scoped_time_ms'])} |"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--case", default=None)
    parser.add_argument(
        "--csv",
        type=Path,
        default=STATE_DIR / "random-k-sweep-summary.csv",
        help="CSV path to write. Use --csv /dev/null to suppress a useful file.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = summarize(args.state_dir, args.case)
    if str(args.csv) != "/dev/null":
        write_csv(rows, args.csv)
    print_markdown(rows)
    if str(args.csv) != "/dev/null":
        print(f"\nCSV: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
