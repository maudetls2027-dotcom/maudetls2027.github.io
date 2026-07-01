#!/usr/bin/env python3
"""Summarize RQ1 generation-time JSONL results for Table II."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean


PATTERNS = ("P1", "P2", "P3", "P4", "P5")
PROTOCOL_LABELS = {"tls12": "TLS 1.2", "tls13": "TLS 1.3"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rq1_dir() -> Path:
    return repo_root() / "maude" / "scenario" / "rq1"


def load_records(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_no}") from exc
    return records


def is_usable(record: dict[str, object]) -> bool:
    return (
        record.get("timeout") is False
        and record.get("returncode") == 0
        and isinstance(record.get("maude_real_ms"), int)
        and isinstance(record.get("elapsed_sec"), (int, float))
    )


def summarize_jobs(records: list[dict[str, object]]) -> list[dict[str, object]]:
    by_job: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        by_job[str(record["job_id"])].append(record)

    summaries: list[dict[str, object]] = []
    for job_id, rows in sorted(by_job.items()):
        first = rows[0]
        usable = [row for row in rows if is_usable(row)]
        maude_values = [int(row["maude_real_ms"]) for row in usable]
        elapsed_values = [float(row["elapsed_sec"]) for row in usable]
        solution_values = [int(row["solutions"]) for row in usable if isinstance(row.get("solutions"), int)]
        expected_instances = int(first["expected_instances"])
        summaries.append(
            {
                "job_id": job_id,
                "protocol": first["protocol"],
                "pattern": first["pattern"],
                "source_id": first["source_id"],
                "chunk_id": first["chunk_id"],
                "scenario_kind": first["scenario_kind"],
                "expected_instances": expected_instances,
                "total_runs": len(rows),
                "usable_runs": len(usable),
                "failed_runs": len(rows) - len(usable),
                "count_mismatches": sum(1 for row in rows if bool(row.get("count_mismatch"))),
                "avg_maude_real_ms": mean(maude_values) if maude_values else None,
                "avg_elapsed_sec": mean(elapsed_values) if elapsed_values else None,
                "avg_solutions": mean(solution_values) if solution_values else None,
            }
        )
    return summaries


def summarize_groups(job_summaries: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in job_summaries:
        grouped[(str(row["protocol"]), str(row["pattern"]))].append(row)

    summaries: list[dict[str, object]] = []
    for protocol in ("tls12", "tls13"):
        for pattern in PATTERNS:
            rows = grouped.get((protocol, pattern), [])
            if not rows:
                continue
            usable_jobs = [row for row in rows if row["avg_maude_real_ms"] is not None]
            total_expected = sum(int(row["expected_instances"]) for row in rows)
            total_maude_ms = sum(float(row["avg_maude_real_ms"]) for row in usable_jobs)
            total_elapsed_sec = sum(float(row["avg_elapsed_sec"]) for row in usable_jobs)
            summaries.append(
                {
                    "protocol": protocol,
                    "pattern": pattern,
                    "jobs": len(rows),
                    "usable_jobs": len(usable_jobs),
                    "total_runs": sum(int(row["total_runs"]) for row in rows),
                    "usable_runs": sum(int(row["usable_runs"]) for row in rows),
                    "failed_runs": sum(int(row["failed_runs"]) for row in rows),
                    "count_mismatches": sum(int(row["count_mismatches"]) for row in rows),
                    "expected_instances": total_expected,
                    "observed_solutions": sum(
                        float(row["avg_solutions"]) for row in usable_jobs if row["avg_solutions"] is not None
                    ),
                    "total_maude_real_sec": total_maude_ms / 1000.0,
                    "total_elapsed_sec": total_elapsed_sec,
                    "avg_maude_real_ms_per_instance": (
                        total_maude_ms / total_expected if total_expected else None
                    ),
                }
            )
    return summaries


def summarize_protocols(group_summaries: list[dict[str, object]]) -> list[dict[str, object]]:
    by_protocol: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in group_summaries:
        by_protocol[str(row["protocol"])].append(row)

    protocol_rows: list[dict[str, object]] = []
    for protocol in ("tls12", "tls13"):
        rows = by_protocol.get(protocol, [])
        if not rows:
            continue
        expected = sum(int(row["expected_instances"]) for row in rows)
        total_maude_sec = sum(float(row["total_maude_real_sec"]) for row in rows)
        protocol_rows.append(
            {
                "protocol": protocol,
                "pattern": "ALL",
                "jobs": sum(int(row["jobs"]) for row in rows),
                "usable_jobs": sum(int(row["usable_jobs"]) for row in rows),
                "total_runs": sum(int(row["total_runs"]) for row in rows),
                "usable_runs": sum(int(row["usable_runs"]) for row in rows),
                "failed_runs": sum(int(row["failed_runs"]) for row in rows),
                "count_mismatches": sum(int(row["count_mismatches"]) for row in rows),
                "expected_instances": expected,
                "observed_solutions": sum(float(row["observed_solutions"]) for row in rows),
                "total_maude_real_sec": total_maude_sec,
                "total_elapsed_sec": sum(float(row["total_elapsed_sec"]) for row in rows),
                "avg_maude_real_ms_per_instance": (
                    (total_maude_sec * 1000.0) / expected if expected else None
                ),
            }
        )
    return protocol_rows


def status_text(row: dict[str, object]) -> str:
    if int(row["failed_runs"]) > 0:
        return f"failed runs: {row['failed_runs']}"
    if int(row["count_mismatches"]) > 0:
        return f"count mismatches: {row['count_mismatches']}"
    if int(row["usable_jobs"]) < int(row["jobs"]):
        return "partial"
    return "ok"


def fmt_sec(value: object) -> str:
    if value is None:
        return ""
    return f"{float(value):.3f}"


def fmt_ms(value: object) -> str:
    if value is None:
        return ""
    return f"{float(value):.3f}"


def write_csv(path: Path, protocol_rows: list[dict[str, object]], group_rows: list[dict[str, object]]) -> None:
    columns = [
        "protocol",
        "pattern",
        "jobs",
        "usable_jobs",
        "total_runs",
        "usable_runs",
        "failed_runs",
        "count_mismatches",
        "expected_instances",
        "observed_solutions",
        "total_maude_real_sec",
        "total_elapsed_sec",
        "avg_maude_real_ms_per_instance",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=columns)
        writer.writeheader()
        for row in protocol_rows + group_rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def write_markdown(
    path: Path,
    protocol_rows: list[dict[str, object]],
    group_rows: list[dict[str, object]],
    results: Path,
) -> None:
    lines: list[str] = [
        "# RQ1 Generation-Time Summary",
        "",
        f"Source JSONL: `{results}`",
        "",
        "Total Time is the sum of Maude `real` time from `set stats on`. "
        "When a job has repeated runs, its Maude time is averaged before protocol and pattern totals are summed.",
        "",
        "## Table II Draft",
        "",
        "| Protocol | Test Case # | Total Time (s) | Avg Time / Case (ms) | Jobs | Status |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for row in protocol_rows:
        label = PROTOCOL_LABELS.get(str(row["protocol"]), str(row["protocol"]))
        lines.append(
            f"| {label} | {row['expected_instances']} | {fmt_sec(row['total_maude_real_sec'])} | "
            f"{fmt_ms(row['avg_maude_real_ms_per_instance'])} | {row['jobs']} | {status_text(row)} |"
        )

    lines.extend(
        [
            "",
            "## Pattern Breakdown",
            "",
            "| Protocol | Pattern | Test Case # | Total Time (s) | Avg Time / Case (ms) | Jobs | Status |",
            "|---|---|---:|---:|---:|---:|---|",
        ]
    )
    for row in group_rows:
        label = PROTOCOL_LABELS.get(str(row["protocol"]), str(row["protocol"]))
        lines.append(
            f"| {label} | {row['pattern']} | {row['expected_instances']} | "
            f"{fmt_sec(row['total_maude_real_sec'])} | "
            f"{fmt_ms(row['avg_maude_real_ms_per_instance'])} | {row['jobs']} | {status_text(row)} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    default_results = rq1_dir() / "state" / "generation-time-matrix.jsonl"
    parser = argparse.ArgumentParser(description="Summarize RQ1 generation-time JSONL results.")
    parser.add_argument("--results", default=str(default_results), help="Input JSONL file.")
    parser.add_argument(
        "--csv",
        default=str(rq1_dir() / "state" / "generation-time-summary.csv"),
        help="Output CSV summary.",
    )
    parser.add_argument(
        "--markdown",
        default=str(rq1_dir() / "state" / "generation-time-summary.md"),
        help="Output Markdown summary.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = Path(args.results).expanduser()
    if not results.exists():
        raise FileNotFoundError(f"missing results file: {results}")

    records = load_records(results)
    if not records:
        raise ValueError(f"empty results file: {results}")

    job_rows = summarize_jobs(records)
    group_rows = summarize_groups(job_rows)
    protocol_rows = summarize_protocols(group_rows)

    write_csv(Path(args.csv).expanduser(), protocol_rows, group_rows)
    write_markdown(Path(args.markdown).expanduser(), protocol_rows, group_rows, results)
    print(f"[rq1-summary] wrote {args.csv}")
    print(f"[rq1-summary] wrote {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
