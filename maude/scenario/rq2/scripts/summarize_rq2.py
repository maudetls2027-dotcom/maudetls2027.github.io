#!/usr/bin/env python3
"""Summarize RQ2 JSONL measurements for Table IV."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean


PROTOCOL_LABELS = {"tls12": "TLS 1.2", "tls13": "TLS 1.3", "mixed": "Mixed"}
MODES = ("candidate", "success")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rq2_dir() -> Path:
    return repo_root() / "maude" / "scenario" / "rq2"


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
        and isinstance(record.get("solutions"), int)
        and isinstance(record.get("maude_real_ms"), int)
        and isinstance(record.get("elapsed_sec"), (int, float))
    )


def fmt_sec(value: object) -> str:
    if value is None:
        return ""
    return f"{float(value):.3f}"


def avg_or_none(values: list[float]) -> float | None:
    return mean(values) if values else None


def summarize_phase(rows: list[dict[str, object]]) -> dict[str, object]:
    usable = [row for row in rows if is_usable(row)]
    solution_values = [int(row["solutions"]) for row in usable]
    distinct_counts = sorted(set(solution_values))
    return {
        "runs": len(rows),
        "usable_runs": len(usable),
        "failed_runs": len(rows) - len(usable),
        "count": distinct_counts[0] if len(distinct_counts) == 1 else None,
        "count_values": distinct_counts,
        "count_mismatch": len(distinct_counts) > 1,
        "maude_real_sec": avg_or_none([int(row["maude_real_ms"]) / 1000.0 for row in usable]),
        "elapsed_sec": avg_or_none([float(row["elapsed_sec"]) for row in usable]),
        "cap_reached": any(bool(row.get("cap_reached")) for row in rows),
    }


def status_text(candidate: dict[str, object] | None, success: dict[str, object] | None) -> str:
    phases = [phase for phase in (candidate, success) if phase is not None]
    if not phases:
        return "missing"
    if any(int(phase["failed_runs"]) > 0 for phase in phases):
        return "failed"
    if any(bool(phase["count_mismatch"]) for phase in phases):
        return "count-mismatch"
    if any(bool(phase["cap_reached"]) for phase in phases):
        return "cap-reached"
    return "ok"


def summarize_cves(records: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for record in records:
        grouped[(str(record["case_id"]), str(record["mode"]))].append(record)

    case_ids = sorted({case_id for case_id, _mode in grouped})
    rows: list[dict[str, object]] = []
    for case_id in case_ids:
        phase_rows = {mode: grouped.get((case_id, mode), []) for mode in MODES}
        first = next((items[0] for items in phase_rows.values() if items), None)
        if first is None:
            continue
        candidate = summarize_phase(phase_rows["candidate"]) if phase_rows["candidate"] else None
        success = summarize_phase(phase_rows["success"]) if phase_rows["success"] else None
        rows.append(
            {
                "case_id": case_id,
                "cve": first["cve"],
                "library": first["library"],
                "protocol": first["protocol"],
                "aggregation_protocol": first["aggregation_protocol"],
                "protocol_version": first["protocol_version"],
                "test_case_failures_static": first["test_case_failures_static"],
                "candidate_count": candidate["count"] if candidate else None,
                "candidate_maude_real_sec": candidate["maude_real_sec"] if candidate else None,
                "candidate_elapsed_sec": candidate["elapsed_sec"] if candidate else None,
                "candidate_runs": candidate["runs"] if candidate else 0,
                "candidate_usable_runs": candidate["usable_runs"] if candidate else 0,
                "candidate_cap_reached": candidate["cap_reached"] if candidate else False,
                "success_count": success["count"] if success else None,
                "success_maude_real_sec": success["maude_real_sec"] if success else None,
                "success_elapsed_sec": success["elapsed_sec"] if success else None,
                "success_runs": success["runs"] if success else 0,
                "success_usable_runs": success["usable_runs"] if success else 0,
                "success_cap_reached": success["cap_reached"] if success else False,
                "failed_runs": (candidate["failed_runs"] if candidate else 0) + (success["failed_runs"] if success else 0),
                "count_mismatches": int(bool(candidate and candidate["count_mismatch"]))
                + int(bool(success and success["count_mismatch"])),
                "status": status_text(candidate, success),
            }
        )
    return rows


def summarize_versions(cve_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in cve_rows:
        grouped[str(row["aggregation_protocol"])].append(row)

    version_rows: list[dict[str, object]] = []
    for protocol in ("tls12", "tls13", "mixed"):
        rows = grouped.get(protocol, [])
        if not rows:
            continue
        usable = [row for row in rows if row["status"] == "ok"]
        cap_reached = any(row["candidate_cap_reached"] or row["success_cap_reached"] for row in rows)
        failed = sum(int(row["failed_runs"]) for row in rows)
        mismatches = sum(int(row["count_mismatches"]) for row in rows)
        if failed:
            status = "failed"
        elif mismatches:
            status = "count-mismatch"
        elif cap_reached:
            status = "cap-reached"
        elif len(usable) != len(rows):
            status = "partial"
        else:
            status = "ok"
        version_rows.append(
            {
                "aggregation_protocol": protocol,
                "tls_version": PROTOCOL_LABELS.get(protocol, protocol),
                "cves": len(rows),
                "usable_cves": len(usable),
                "test_case_failures_static": sum(int(row["test_case_failures_static"]) for row in rows),
                "candidate_count": sum(int(row["candidate_count"] or 0) for row in rows),
                "candidate_maude_real_sec": sum(float(row["candidate_maude_real_sec"] or 0.0) for row in rows),
                "success_count": sum(int(row["success_count"] or 0) for row in rows),
                "success_maude_real_sec": sum(float(row["success_maude_real_sec"] or 0.0) for row in rows),
                "failed_runs": failed,
                "count_mismatches": mismatches,
                "cap_reached": cap_reached,
                "status": status,
            }
        )
    return version_rows


def component_key(record: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(record["case_id"]),
        str(record.get("experiment") or "legacy"),
        str(record.get("bucket_id") or ""),
    )


def summarize_new_components(records: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, object]]] = defaultdict(list)
    for record in records:
        if str(record.get("experiment")) not in {"baseline", "bucket"}:
            continue
        case_id, experiment, bucket_id = component_key(record)
        grouped[(case_id, experiment, bucket_id, str(record["mode"]))].append(record)

    component_keys = sorted({key[:3] for key in grouped})
    rows: list[dict[str, object]] = []
    for case_id, experiment, bucket_id in component_keys:
        phase_rows = {
            mode: grouped.get((case_id, experiment, bucket_id, mode), [])
            for mode in MODES
        }
        first = next((items[0] for items in phase_rows.values() if items), None)
        if first is None:
            continue
        candidate = summarize_phase(phase_rows["candidate"]) if phase_rows["candidate"] else None
        success = summarize_phase(phase_rows["success"]) if phase_rows["success"] else None
        rows.append(
            {
                "case_id": case_id,
                "cve": first["cve"],
                "library": first["library"],
                "protocol": first["protocol"],
                "aggregation_protocol": first["aggregation_protocol"],
                "protocol_version": first["protocol_version"],
                "test_case_failures_static": first["test_case_failures_static"],
                "experiment": experiment,
                "bucket_id": bucket_id,
                "category": first.get("category", ""),
                "pattern": first.get("pattern", ""),
                "bucket_expected_instances": first.get("bucket_expected_instances", ""),
                "candidate_count": candidate["count"] if candidate else None,
                "candidate_maude_real_sec": candidate["maude_real_sec"] if candidate else None,
                "candidate_elapsed_sec": candidate["elapsed_sec"] if candidate else None,
                "candidate_runs": candidate["runs"] if candidate else 0,
                "candidate_usable_runs": candidate["usable_runs"] if candidate else 0,
                "candidate_cap_reached": candidate["cap_reached"] if candidate else False,
                "success_count": success["count"] if success else None,
                "success_maude_real_sec": success["maude_real_sec"] if success else None,
                "success_elapsed_sec": success["elapsed_sec"] if success else None,
                "success_runs": success["runs"] if success else 0,
                "success_usable_runs": success["usable_runs"] if success else 0,
                "success_cap_reached": success["cap_reached"] if success else False,
                "failed_runs": (candidate["failed_runs"] if candidate else 0) + (success["failed_runs"] if success else 0),
                "count_mismatches": int(bool(candidate and candidate["count_mismatch"]))
                + int(bool(success and success["count_mismatch"])),
                "status": status_text(candidate, success),
            }
        )
    return rows


def summarize_new_cves(component_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in component_rows:
        grouped[str(row["case_id"])].append(row)

    rows: list[dict[str, object]] = []
    for case_id in sorted(grouped):
        components = grouped[case_id]
        first = components[0]
        failed = sum(int(row["failed_runs"]) for row in components)
        mismatches = sum(int(row["count_mismatches"]) for row in components)
        cap_reached = any(row["candidate_cap_reached"] or row["success_cap_reached"] for row in components)
        if failed:
            status = "failed"
        elif mismatches:
            status = "count-mismatch"
        elif cap_reached:
            status = "cap-reached"
        elif any(row["status"] != "ok" for row in components):
            status = "partial"
        else:
            status = "ok"
        rows.append(
            {
                "case_id": case_id,
                "cve": first["cve"],
                "library": first["library"],
                "protocol": first["protocol"],
                "aggregation_protocol": first["aggregation_protocol"],
                "protocol_version": first["protocol_version"],
                "test_case_failures_static": first["test_case_failures_static"],
                "candidate_count": sum(int(row["candidate_count"] or 0) for row in components),
                "candidate_maude_real_sec": sum(float(row["candidate_maude_real_sec"] or 0.0) for row in components),
                "candidate_elapsed_sec": sum(float(row["candidate_elapsed_sec"] or 0.0) for row in components),
                "candidate_runs": sum(int(row["candidate_runs"]) for row in components),
                "candidate_usable_runs": sum(int(row["candidate_usable_runs"]) for row in components),
                "candidate_cap_reached": any(bool(row["candidate_cap_reached"]) for row in components),
                "success_count": sum(int(row["success_count"] or 0) for row in components),
                "success_maude_real_sec": sum(float(row["success_maude_real_sec"] or 0.0) for row in components),
                "success_elapsed_sec": sum(float(row["success_elapsed_sec"] or 0.0) for row in components),
                "success_runs": sum(int(row["success_runs"]) for row in components),
                "success_usable_runs": sum(int(row["success_usable_runs"]) for row in components),
                "success_cap_reached": any(bool(row["success_cap_reached"]) for row in components),
                "component_rows": len(components),
                "bucket_rows": sum(1 for row in components if row["experiment"] == "bucket"),
                "failed_runs": failed,
                "count_mismatches": mismatches,
                "status": status,
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, object]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def write_markdown(
    path: Path,
    cve_rows: list[dict[str, object]],
    version_rows: list[dict[str, object]],
    results: Path,
    component_rows: list[dict[str, object]] | None = None,
) -> None:
    component_rows = component_rows or []
    lines = [
        "# RQ2 Table IV Summary",
        "",
        f"Source JSONL: `{results}`",
        "",
        "Candidate time is the averaged Maude `real` time for candidate runs. "
        "Success time is reported for inspection, but Table IV uses candidate time as Exploit Test Case Generation Time.",
        "",
        "## Table IV Draft by CVE",
        "",
        "| CVE | Library | Version | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Success Time (s) | Status |",
        "|---|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in cve_rows:
        version = PROTOCOL_LABELS.get(str(row["aggregation_protocol"]), str(row["aggregation_protocol"]))
        lines.append(
            f"| {row['cve']} | {row['library']} | {version} | {row['test_case_failures_static']} | "
            f"{row['candidate_count'] if row['candidate_count'] is not None else ''} | "
            f"{fmt_sec(row['candidate_maude_real_sec'])} | "
            f"{row['success_count'] if row['success_count'] is not None else ''} | "
            f"{fmt_sec(row['success_maude_real_sec'])} | {row['status']} |"
        )

    lines.extend(
        [
            "",
            "## Version Aggregation",
            "",
            "| Version | CVEs | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Status |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    for row in version_rows:
        lines.append(
            f"| {row['tls_version']} | {row['cves']} | {row['test_case_failures_static']} | "
            f"{row['candidate_count']} | {fmt_sec(row['candidate_maude_real_sec'])} | "
            f"{row['success_count']} | {row['status']} |"
        )
    bucket_rows = [row for row in component_rows if row.get("experiment") == "bucket"]
    if bucket_rows:
        lines.extend(
            [
                "",
                "## Bucket Breakdown",
                "",
                "| CVE | Version | Category | Pattern | Bucket Instances | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Status |",
                "|---|---|---|---|---:|---:|---:|---:|---|",
            ]
        )
        for row in bucket_rows:
            version = PROTOCOL_LABELS.get(str(row["aggregation_protocol"]), str(row["aggregation_protocol"]))
            lines.append(
                f"| {row['cve']} | {version} | {row['category']} | {row['pattern']} | "
                f"{row['bucket_expected_instances']} | "
                f"{row['candidate_count'] if row['candidate_count'] is not None else ''} | "
                f"{fmt_sec(row['candidate_maude_real_sec'])} | "
                f"{row['success_count'] if row['success_count'] is not None else ''} | {row['status']} |"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    default_results = rq2_dir() / "state" / "jsonl" / "rq2-matrix.jsonl"
    parser = argparse.ArgumentParser(description="Summarize RQ2 Table IV JSONL results.")
    parser.add_argument("--results", default=str(default_results), help="Input JSONL file.")
    parser.add_argument(
        "--cve-csv",
        default=str(rq2_dir() / "state" / "csv" / "rq2-cve-summary.csv"),
        help="Output CVE-level CSV.",
    )
    parser.add_argument(
        "--version-csv",
        default=str(rq2_dir() / "state" / "csv" / "rq2-version-summary.csv"),
        help="Output version-level CSV.",
    )
    parser.add_argument(
        "--bucket-csv",
        default=str(rq2_dir() / "state" / "csv" / "rq2-bucket-summary.csv"),
        help="Output bucket/component-level CSV for baseline+bucket runs.",
    )
    parser.add_argument(
        "--markdown",
        default=str(rq2_dir() / "state" / "md" / "rq2-summary.md"),
        help="Output Markdown summary.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = Path(args.results)
    records = load_records(results)
    has_new_records = any(record.get("experiment") in {"baseline", "bucket"} for record in records)
    component_rows: list[dict[str, object]] = []
    if has_new_records:
        component_rows = summarize_new_components(records)
        cve_rows = summarize_new_cves(component_rows)
    else:
        cve_rows = summarize_cves(records)
    version_rows = summarize_versions(cve_rows)

    cve_columns = [
        "case_id",
        "cve",
        "library",
        "protocol",
        "aggregation_protocol",
        "test_case_failures_static",
        "candidate_count",
        "candidate_maude_real_sec",
        "candidate_elapsed_sec",
        "candidate_runs",
        "candidate_usable_runs",
        "candidate_cap_reached",
        "success_count",
        "success_maude_real_sec",
        "success_elapsed_sec",
        "success_runs",
        "success_usable_runs",
        "success_cap_reached",
        "component_rows",
        "bucket_rows",
        "failed_runs",
        "count_mismatches",
        "status",
    ]
    component_columns = [
        "case_id",
        "cve",
        "library",
        "protocol",
        "aggregation_protocol",
        "experiment",
        "bucket_id",
        "category",
        "pattern",
        "bucket_expected_instances",
        "test_case_failures_static",
        "candidate_count",
        "candidate_maude_real_sec",
        "candidate_elapsed_sec",
        "candidate_runs",
        "candidate_usable_runs",
        "candidate_cap_reached",
        "success_count",
        "success_maude_real_sec",
        "success_elapsed_sec",
        "success_runs",
        "success_usable_runs",
        "success_cap_reached",
        "failed_runs",
        "count_mismatches",
        "status",
    ]
    version_columns = [
        "aggregation_protocol",
        "tls_version",
        "cves",
        "usable_cves",
        "test_case_failures_static",
        "candidate_count",
        "candidate_maude_real_sec",
        "success_count",
        "success_maude_real_sec",
        "failed_runs",
        "count_mismatches",
        "cap_reached",
        "status",
    ]
    write_csv(Path(args.cve_csv), cve_rows, cve_columns)
    write_csv(Path(args.version_csv), version_rows, version_columns)
    if has_new_records:
        write_csv(Path(args.bucket_csv), component_rows, component_columns)
    write_markdown(Path(args.markdown), cve_rows, version_rows, results, component_rows)
    print(f"wrote {args.cve_csv}")
    print(f"wrote {args.version_csv}")
    if has_new_records:
        print(f"wrote {args.bucket_csv}")
    print(f"wrote {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
