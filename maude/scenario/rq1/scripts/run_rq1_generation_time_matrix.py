#!/usr/bin/env python3
"""Run RQ1 P1-P5 generation-time measurements from the generated manifest."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


PATTERNS = ("P1", "P2", "P3", "P4", "P5")
PROTOCOLS = ("tls12", "tls13")
REWRITES_RE = re.compile(
    r"rewrites:\s+([0-9,]+)\s+in\s+([0-9,]+)ms cpu\s+\(([0-9,]+)ms real\)"
)
RESULT_RE = re.compile(r"^result\s+[^:]+:\s*(.+?)\s*$")
SAFE_TAG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rq1_dir() -> Path:
    return repo_root() / "maude" / "scenario" / "rq1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_tag(value: str) -> str:
    return SAFE_TAG_RE.sub("_", value.strip())


def run_generator() -> None:
    generator = rq1_dir() / "scripts" / "generate_aggregates.py"
    subprocess.run([sys.executable, str(generator)], cwd=repo_root(), check=True)


def load_manifest() -> list[dict[str, object]]:
    manifest_path = rq1_dir() / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing manifest: {manifest_path}")
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return list(data["jobs"])


def select_values(values: list[str], allowed: tuple[str, ...], label: str) -> set[str]:
    if not values or "all" in values:
        return set(allowed)
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise ValueError(f"unknown {label}: {', '.join(unknown)}")
    return set(values)


def select_jobs(args: argparse.Namespace, manifest_jobs: list[dict[str, object]]) -> list[dict[str, object]]:
    protocols = select_values(args.protocols, PROTOCOLS, "protocols")
    patterns = select_values(args.patterns, PATTERNS, "patterns")
    job_ids = {str(job["job_id"]) for job in manifest_jobs}

    if not args.jobs or "all" in args.jobs:
        selected_ids = job_ids
    else:
        selected_ids = set(args.jobs)
        unknown = sorted(selected_ids - job_ids)
        if unknown:
            raise ValueError(f"unknown jobs: {', '.join(unknown)}")

    selected = [
        job
        for job in manifest_jobs
        if str(job["protocol"]) in protocols
        and str(job["pattern"]) in patterns
        and str(job["job_id"]) in selected_ids
    ]
    selected.sort(key=lambda job: (str(job["protocol"]), str(job["pattern"]), str(job["job_id"])))
    return selected


def list_jobs(jobs: list[dict[str, object]]) -> None:
    print("job_id\tprotocol\tpattern\texpected_instances\tscenario_kind\tscens")
    for job in jobs:
        scens = ",".join(str(value) for value in job["scens"])
        print(
            f"{job['job_id']}\t{job['protocol']}\t{job['pattern']}\t"
            f"{job['expected_instances']}\t{job['scenario_kind']}\t{scens}"
        )


def driver_stem(job: dict[str, object], repeat: int, repeat_count: int, tag: str) -> str:
    repeat_suffix = f".r{repeat}" if repeat_count > 1 else ""
    tag_suffix = f".{safe_tag(tag)}" if tag else ""
    return f"{job['job_id']}{repeat_suffix}{tag_suffix}.generation"


def make_driver(job: dict[str, object], repeat: int, args: argparse.Namespace) -> Path:
    raw_dir = rq1_dir() / "state" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    driver = raw_dir / f"{driver_stem(job, repeat, args.repeat, args.tag)}.maude"

    cap = int(job["expected_instances"]) + 1
    property_expr = str(job.get("property_op") or f"{job['scenario_op']}({job['labels_op']})")
    driver.write_text(
        f"""load ../../{job['module_file']}

set stats on .

red in {job['module_name']} : rq1CountUpTo(
  {job['protocol_version']},
  initialCWA,
  {job['conf_op']},
  {job['bds_op']},
  {property_expr},
  0,
  {cap}
) .

quit
""",
        encoding="utf-8",
    )
    return driver


def parse_output(stdout: str, stderr: str) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for line in (stdout + "\n" + stderr).splitlines():
        result_match = RESULT_RE.match(line.strip())
        if result_match:
            result = result_match.group(1)
            parsed["result"] = result
            if re.fullmatch(r"[0-9]+", result):
                parsed["solutions"] = int(result)

        rewrite_match = REWRITES_RE.search(line)
        if rewrite_match:
            parsed["maude_stats"] = line.strip()
            parsed["rewrites"] = int(rewrite_match.group(1).replace(",", ""))
            parsed["maude_cpu_ms"] = int(rewrite_match.group(2).replace(",", ""))
            parsed["maude_real_ms"] = int(rewrite_match.group(3).replace(",", ""))
    return parsed


def kill_process_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_maude(maude_bin: Path, driver: Path, timeout: int) -> dict[str, object]:
    started = time.monotonic()
    proc = subprocess.Popen(
        [str(maude_bin), "-no-advise", str(driver)],
        cwd=repo_root(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        elapsed = time.monotonic() - started
        return {
            "timeout": False,
            "returncode": proc.returncode,
            "elapsed_sec": elapsed,
            "stdout": stdout,
            "stderr": stderr,
            **parse_output(stdout, stderr),
        }
    except subprocess.TimeoutExpired:
        kill_process_group(proc)
        stdout, stderr = proc.communicate()
        elapsed = time.monotonic() - started
        return {
            "timeout": True,
            "returncode": None,
            "elapsed_sec": elapsed,
            "stdout": stdout,
            "stderr": stderr,
            **parse_output(stdout, stderr),
        }
    except KeyboardInterrupt:
        kill_process_group(proc)
        proc.communicate()
        raise


def run_one(
    job: dict[str, object],
    repeat: int,
    args: argparse.Namespace,
    write_lock: threading.Lock,
) -> dict[str, object]:
    root = repo_root()
    raw_dir = rq1_dir() / "state" / "raw"
    driver = make_driver(job, repeat, args)
    stem = driver_stem(job, repeat, args.repeat, args.tag)
    stdout_path = raw_dir / f"{stem}.out"
    stderr_path = raw_dir / f"{stem}.err"

    record: dict[str, object] = {
        "started_at": utc_now(),
        "repeat": repeat,
        "tag": args.tag,
        "maude_bin": str(args.maude_bin),
        "timeout_sec": args.timeout,
        "driver": str(driver.relative_to(root)),
        **job,
    }

    print(
        f"[rq1] start job={job['job_id']} repeat={repeat} "
        f"expected={job['expected_instances']}",
        flush=True,
    )
    result = run_maude(Path(args.maude_bin), driver, args.timeout)
    stdout_path.write_text(str(result.pop("stdout")), encoding="utf-8")
    stderr_path.write_text(str(result.pop("stderr")), encoding="utf-8")

    record.update(result)
    record["finished_at"] = utc_now()
    record["stdout_path"] = str(stdout_path.relative_to(root))
    record["stderr_path"] = str(stderr_path.relative_to(root))
    record["success"] = (
        not bool(record.get("timeout"))
        and record.get("returncode") == 0
        and isinstance(record.get("solutions"), int)
    )
    record["count_mismatch"] = (
        isinstance(record.get("solutions"), int)
        and int(record["solutions"]) != int(job["expected_instances"])
    )

    with write_lock:
        with Path(args.results).open("a", encoding="utf-8") as out:
            out.write(json.dumps(record, sort_keys=True) + "\n")

    status = "timeout" if record["timeout"] else f"rc={record['returncode']}"
    maude_real = record.get("maude_real_ms")
    maude_real_text = f" maude_real={maude_real / 1000:.3f}s" if isinstance(maude_real, int) else ""
    solutions = record.get("solutions")
    solutions_text = f" solutions={solutions}" if solutions is not None else ""
    mismatch_text = " count_mismatch" if record["count_mismatch"] else ""
    print(
        f"[rq1] done job={job['job_id']} repeat={repeat} {status} "
        f"elapsed={record['elapsed_sec']:.3f}s{maude_real_text}{solutions_text}{mismatch_text}",
        flush=True,
    )
    return record


def summarize(results: Path) -> None:
    script = rq1_dir() / "scripts" / "summarize_generation_time.py"
    if script.exists():
        subprocess.run([sys.executable, str(script), "--results", str(results)], cwd=repo_root(), check=True)


def parse_args() -> argparse.Namespace:
    root = repo_root()
    default_maude = root / "maude" / "maude" / "maude-3.5.1" / "maude"
    default_results = rq1_dir() / "state" / "generation-time-matrix.jsonl"

    parser = argparse.ArgumentParser(
        description="Measure RQ1 P1-P5 generation time by running aggregate RFC scenarios."
    )
    parser.add_argument("--patterns", nargs="+", default=["all"], help="Patterns to run: P1 P2 P3 P4 P5 or all.")
    parser.add_argument("--protocols", nargs="+", default=["all"], help="Protocols to run: tls12 tls13 or all.")
    parser.add_argument("--jobs", nargs="+", default=["all"], help="Manifest job ids to run, or all.")
    parser.add_argument("--list-jobs", action="store_true", help="Print selected jobs and exit.")
    parser.add_argument("--repeat", type=int, default=1, help="Number of repeats per selected job.")
    parser.add_argument("--parallel", type=int, default=1, help="Number of parallel Maude processes.")
    parser.add_argument("--timeout", type=int, default=86400, help="Per-job timeout in seconds.")
    parser.add_argument("--maude-bin", default=str(default_maude), help="Maude executable path.")
    parser.add_argument("--results", default=str(default_results), help="JSONL result file.")
    parser.add_argument("--tag", default="", help="Optional filename/result tag.")
    parser.add_argument("--append", action="store_true", help="Append to an existing result file.")
    parser.add_argument("--no-generate", action="store_true", help="Use existing generated modules and manifest.")
    parser.add_argument("--no-summarize", action="store_true", help="Do not write summary CSV/Markdown after running.")
    parser.add_argument("--strict-counts", action="store_true", help="Treat solution-count mismatches as failures.")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop after the first failed Maude job.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.maude_bin = str(Path(args.maude_bin).expanduser())
    args.results = str(Path(args.results).expanduser())
    if args.repeat < 1:
        raise ValueError("--repeat must be >= 1")
    if args.parallel < 1:
        raise ValueError("--parallel must be >= 1")
    if not Path(args.maude_bin).exists():
        raise FileNotFoundError(f"Maude executable not found: {args.maude_bin}")

    if not args.no_generate:
        run_generator()
    manifest_jobs = load_manifest()
    selected = select_jobs(args, manifest_jobs)

    if args.list_jobs:
        list_jobs(selected)
        return 0
    if not selected:
        print("[rq1] no jobs selected", file=sys.stderr)
        return 1

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    if results_path.exists() and not args.append:
        results_path.unlink()

    work_items = [(job, repeat) for repeat in range(1, args.repeat + 1) for job in selected]
    print(
        f"[rq1] jobs={len(selected)} repeats={args.repeat} work_items={len(work_items)} "
        f"parallel={args.parallel} results={args.results}",
        flush=True,
    )

    write_lock = threading.Lock()
    records: list[dict[str, object]] = []
    try:
        if args.parallel == 1:
            for job, repeat in work_items:
                record = run_one(job, repeat, args, write_lock)
                records.append(record)
                failed = not bool(record.get("success"))
                failed = failed or (args.strict_counts and bool(record.get("count_mismatch")))
                if failed and args.stop_on_error:
                    break
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
                futures = [executor.submit(run_one, job, repeat, args, write_lock) for job, repeat in work_items]
                for future in concurrent.futures.as_completed(futures):
                    record = future.result()
                    records.append(record)
                    failed = not bool(record.get("success"))
                    failed = failed or (args.strict_counts and bool(record.get("count_mismatch")))
                    if failed and args.stop_on_error:
                        raise RuntimeError(f"stopping after failed job {record.get('job_id')}")
    except KeyboardInterrupt:
        print("[rq1] interrupted", file=sys.stderr, flush=True)
        return 130

    if not args.no_summarize:
        summarize(results_path)

    hard_failures = [
        record
        for record in records
        if not bool(record.get("success"))
    ]
    count_failures = [record for record in records if bool(record.get("count_mismatch"))]
    if hard_failures:
        print(f"[rq1] complete with hard failures={len(hard_failures)} results={args.results}", flush=True)
        return 1
    if args.strict_counts and count_failures:
        print(f"[rq1] complete with count mismatches={len(count_failures)} results={args.results}", flush=True)
        return 1
    print(f"[rq1] complete results={args.results}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
