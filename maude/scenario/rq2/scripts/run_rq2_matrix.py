#!/usr/bin/env python3
"""Run RQ2 Table IV candidate/success measurements."""

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


PROTOCOLS = ("tls12", "tls13", "mixed")
MODES = ("candidate", "success")
EXPERIMENTS = ("baseline", "bucket", "legacy")
CATEGORIES = ("5246", "8446", "hrr", "psk")
PATTERNS = ("P1", "P2", "P3", "P4", "P5")
REWRITES_RE = re.compile(
    r"rewrites:\s+([0-9,]+)\s+in\s+([0-9,]+)ms cpu\s+\(([0-9,]+)ms real\)"
)
RESULT_RE = re.compile(r"^result\s+[^:]+:\s*(.+?)\s*$")
SAFE_TAG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rq2_dir() -> Path:
    return repo_root() / "maude" / "scenario" / "rq2"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_tag(value: str) -> str:
    return SAFE_TAG_RE.sub("_", value.strip())


def run_generator(maude_bin: str) -> None:
    generator = rq2_dir() / "scripts" / "generate_rq2_modules.py"
    subprocess.run(
        [sys.executable, str(generator), "--maude-bin", maude_bin, "--reuse-materialized"],
        cwd=repo_root(),
        check=True,
    )


def load_manifest() -> dict[str, object]:
    manifest_path = rq2_dir() / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing manifest: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def select_values(values: list[str], allowed: tuple[str, ...], label: str) -> set[str]:
    if not values or "all" in values:
        return set(allowed)
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise ValueError(f"unknown {label}: {', '.join(unknown)}")
    return set(values)


def select_modes(values: list[str]) -> set[str]:
    if not values or "both" in values or "all" in values:
        return set(MODES)
    return select_values(values, MODES, "modes")


def select_experiments(values: list[str]) -> set[str]:
    if not values or "all" in values:
        return set(EXPERIMENTS)
    return select_values(values, EXPERIMENTS, "experiments")


def select_categories(values: list[str]) -> set[str]:
    return select_values(values, CATEGORIES, "categories") if values and "all" not in values else set(CATEGORIES)


def select_patterns(values: list[str]) -> set[str]:
    return select_values(values, PATTERNS, "patterns") if values and "all" not in values else set(PATTERNS)


def make_measurement_job(
    cve: dict[str, object],
    mode: str,
    experiment: str,
    bucket: dict[str, object] | None = None,
) -> dict[str, object]:
    if experiment == "baseline":
        bds_op = str(cve["baseline_bds_op"])
        property_op = (
            str(cve["baseline_candidate_property_op"])
            if mode == "candidate"
            else str(cve["baseline_success_property_op"])
        )
        bucket_id_value = ""
    elif experiment == "bucket" and bucket is not None:
        bds_op = str(bucket["bds_op"])
        property_op = (
            str(bucket["candidate_property_op"]) if mode == "candidate" else str(bucket["success_property_op"])
        )
        bucket_id_value = str(bucket["bucket_id"])
    elif experiment == "legacy":
        bds_op = str(cve["rq2_bds_op"])
        property_op = str(cve["candidate_property_op"]) if mode == "candidate" else str(cve["success_property_op"])
        bucket_id_value = ""
    else:
        raise ValueError(f"invalid measurement job experiment={experiment} bucket={bucket}")

    job: dict[str, object] = {
        "job_id": ".".join(part for part in [str(cve["case_id"]), experiment, bucket_id_value, mode] if part),
        "experiment": experiment,
        "mode": mode,
        "phase": mode,
        "bucket_id": bucket_id_value,
        "category": str(bucket["category"]) if bucket else "",
        "pattern": str(bucket["pattern"]) if bucket else "",
        "bucket_expected_instances": int(bucket["expected_instances"]) if bucket else None,
        "bucket_set_op": str(bucket["set_op"]) if bucket else "",
        "bucket_step_op": str(bucket["step_op"]) if bucket else "",
        "bds_op": bds_op,
        "property_op": property_op,
        "case_id": cve["case_id"],
        "cve": cve["cve"],
        "library": cve["library"],
        "protocol": cve["protocol"],
        "aggregation_protocol": cve["aggregation_protocol"],
        "protocol_version": cve["protocol_version"],
        "final_version": cve["final_version"],
        "module_file": cve["module_file"],
        "module_name": cve["module_name"],
        "initial_cwa": cve["initial_cwa"],
        "init_conf": cve["init_conf"],
        "source_property_op": cve["source_property_op"],
        "test_case_failures_static": cve["test_case_failures_static"],
        "failure_classes": cve["failure_classes"],
        "count_rule": cve["count_rule"],
    }
    return job


def select_jobs(args: argparse.Namespace, manifest: dict[str, object]) -> list[dict[str, object]]:
    cves = list(manifest["cves"])
    protocols = select_values(args.protocols, PROTOCOLS, "protocols")
    modes = select_modes(args.modes)
    experiments = select_experiments(args.experiments)
    categories = select_categories(args.categories)
    patterns = select_patterns(args.patterns)
    cve_ids = {str(cve["case_id"]) for cve in cves}
    cve_names = {str(cve["cve"]) for cve in cves}
    aliases = cve_ids | cve_names

    if not args.cves or "all" in args.cves:
        selected_aliases = aliases
    else:
        selected_aliases = set(args.cves)
        unknown = sorted(selected_aliases - aliases)
        if unknown:
            raise ValueError(f"unknown CVEs: {', '.join(unknown)}")

    jobs: list[dict[str, object]] = []
    for cve in cves:
        if str(cve["protocol"]) not in protocols:
            continue
        if str(cve["case_id"]) not in selected_aliases and str(cve["cve"]) not in selected_aliases:
            continue
        for mode in sorted(modes):
            if "baseline" in experiments:
                if "baseline_bds_op" not in cve:
                    raise ValueError("manifest does not contain baseline fields; regenerate RQ2 modules")
                jobs.append(make_measurement_job(cve, mode, "baseline"))
            if "bucket" in experiments:
                if "bucket_jobs" not in cve:
                    raise ValueError("manifest does not contain bucket fields; regenerate RQ2 modules")
                for bucket in cve["bucket_jobs"]:
                    if str(bucket["category"]) not in categories:
                        continue
                    if str(bucket["pattern"]) not in patterns:
                        continue
                    jobs.append(make_measurement_job(cve, mode, "bucket", bucket))
            if "legacy" in experiments:
                jobs.append(make_measurement_job(cve, mode, "legacy"))
    jobs.sort(
        key=lambda item: (
            str(item["protocol"]),
            str(item["case_id"]),
            str(item["experiment"]),
            str(item["bucket_id"]),
            str(item["mode"]),
        )
    )
    return jobs


def list_jobs(jobs: list[dict[str, object]]) -> None:
    print("case_id\tcve\tprotocol\texperiment\tcategory\tpattern\tmode\tstatic_failures\tbucket_instances\tmodule\tbds\tproperty")
    for job in jobs:
        print(
            f"{job['case_id']}\t{job['cve']}\t{job['protocol']}\t{job['experiment']}\t"
            f"{job['category']}\t{job['pattern']}\t{job['mode']}\t"
            f"{job['test_case_failures_static']}\t{job['bucket_expected_instances'] or ''}\t"
            f"{job['module_name']}\t{job['bds_op']}\t{job['property_op']}"
        )


def driver_stem(job: dict[str, object], repeat: int, repeat_count: int, tag: str, cap: int | None) -> str:
    repeat_suffix = f".r{repeat}" if repeat_count > 1 else ""
    tag_suffix = f".{safe_tag(tag)}" if tag else ""
    cap_suffix = f".cap{cap}" if cap is not None else ""
    bucket_suffix = f".{safe_tag(str(job['bucket_id']))}" if job.get("bucket_id") else ""
    return (
        f"{job['case_id']}.{job['experiment']}{bucket_suffix}.{job['mode']}"
        f"{cap_suffix}{repeat_suffix}{tag_suffix}.rq2"
    )


def count_expression(job: dict[str, object], cap: int | None) -> str:
    function_name = "rq2CountFrom" if cap is None else "rq2CountUpTo"
    cap_tail = "" if cap is None else f",\n  {cap}"
    return (
        f"{function_name}(\n"
        f"  {job['protocol_version']},\n"
        f"  {job['initial_cwa']},\n"
        f"  {job['init_conf']} tester(N2 . SI) target(N1 . CI),\n"
        f"  {job['bds_op']},\n"
        f"  {job['property_op']},\n"
        f"  0{cap_tail}\n"
        f")"
    )


def make_driver(job: dict[str, object], repeat: int, args: argparse.Namespace) -> Path:
    raw_dir = rq2_dir() / "state" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    driver = raw_dir / f"{driver_stem(job, repeat, args.repeat, args.tag, args.cap)}.maude"
    driver.write_text(
        f"""load ../../{job['module_file']}

set stats on .

red in {job['module_name']} : {count_expression(job, args.cap)} .

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
    raw_dir = rq2_dir() / "state" / "raw"
    driver = make_driver(job, repeat, args)
    stem = driver_stem(job, repeat, args.repeat, args.tag, args.cap)
    stdout_path = raw_dir / f"{stem}.out"
    stderr_path = raw_dir / f"{stem}.err"

    record: dict[str, object] = {
        "schema_version": "rq2-run-v2",
        "rq": "RQ2",
        "record_type": "measurement",
        "started_at": utc_now(),
        "repeat": repeat,
        "tag": args.tag,
        "job_id": job["job_id"],
        "experiment": job["experiment"],
        "mode": job["mode"],
        "phase": job["phase"],
        "bucket_id": job["bucket_id"],
        "category": job["category"],
        "pattern": job["pattern"],
        "bucket_expected_instances": job["bucket_expected_instances"],
        "bucket_set_op": job["bucket_set_op"],
        "bucket_step_op": job["bucket_step_op"],
        "case_id": job["case_id"],
        "cve": job["cve"],
        "library": job["library"],
        "protocol": job["protocol"],
        "aggregation_protocol": job["aggregation_protocol"],
        "protocol_version": job["protocol_version"],
        "final_version": job["final_version"],
        "module_file": job["module_file"],
        "module_name": job["module_name"],
        "initial_cwa": job["initial_cwa"],
        "init_conf": job["init_conf"],
        "bds_op": job["bds_op"],
        "property_op": job["property_op"],
        "source_property_op": job["source_property_op"],
        "test_case_failures_static": job["test_case_failures_static"],
        "failure_classes": job["failure_classes"],
        "count_rule": job["count_rule"],
        "cap": args.cap,
        "maude_bin": str(args.maude_bin),
        "timeout_sec": args.timeout,
        "driver": str(driver.relative_to(root)),
    }

    print(
        f"[rq2] start cve={job['case_id']} experiment={job['experiment']} "
        f"bucket={job['bucket_id'] or '-'} mode={job['mode']} repeat={repeat} cap={args.cap}",
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
        and isinstance(record.get("maude_real_ms"), int)
    )
    record["cap_reached"] = (
        args.cap is not None
        and isinstance(record.get("solutions"), int)
        and int(record["solutions"]) >= int(args.cap)
    )

    with write_lock:
        with Path(args.results).open("a", encoding="utf-8") as out:
            out.write(json.dumps(record, sort_keys=True) + "\n")

    status = "timeout" if record["timeout"] else f"rc={record['returncode']}"
    maude_real = record.get("maude_real_ms")
    real_text = f" maude_real={maude_real / 1000:.3f}s" if isinstance(maude_real, int) else ""
    solution_text = f" solutions={record['solutions']}" if isinstance(record.get("solutions"), int) else ""
    cap_text = " cap_reached" if record.get("cap_reached") else ""
    print(
        f"[rq2] done cve={job['case_id']} experiment={job['experiment']} "
        f"bucket={job['bucket_id'] or '-'} mode={job['mode']} repeat={repeat} {status} "
        f"elapsed={record['elapsed_sec']:.3f}s{real_text}{solution_text}{cap_text}",
        flush=True,
    )
    return record


def summarize(results: Path) -> None:
    script = rq2_dir() / "scripts" / "summarize_rq2.py"
    if script.exists():
        subprocess.run([sys.executable, str(script), "--results", str(results)], cwd=repo_root(), check=True)


def parse_args() -> argparse.Namespace:
    root = repo_root()
    default_maude = root / "maude" / "maude" / "maude-3.5.1" / "maude"
    default_results = rq2_dir() / "state" / "jsonl" / "rq2-matrix.jsonl"
    parser = argparse.ArgumentParser(description="Measure RQ2 Table IV exploit-test-case counts and times.")
    parser.add_argument("--cves", nargs="+", default=["all"], help="CVE case ids, CVE names, or all.")
    parser.add_argument("--protocols", nargs="+", default=["all"], help="Protocols: tls12 tls13 mixed or all.")
    parser.add_argument(
        "--experiments",
        nargs="+",
        default=["baseline", "bucket"],
        help="Experiments: baseline bucket legacy all. Default: baseline bucket.",
    )
    parser.add_argument("--categories", nargs="+", default=["all"], help="RQ1 categories: 5246 8446 hrr psk or all.")
    parser.add_argument("--patterns", nargs="+", default=["all"], help="RQ1 patterns: P1 P2 P3 P4 P5 or all.")
    parser.add_argument("--modes", nargs="+", default=["both"], help="Modes: candidate success both.")
    parser.add_argument("--list-jobs", action="store_true", help="Print selected CVE/mode jobs and exit.")
    parser.add_argument("--repeat", type=int, default=1, help="Number of repeats per selected job.")
    parser.add_argument("--parallel", type=int, default=1, help="Number of parallel Maude processes.")
    parser.add_argument("--timeout", type=int, default=86400, help="Per-job timeout in seconds.")
    parser.add_argument("--cap", type=int, default=None, help="Optional solution cap for bounded smoke runs.")
    parser.add_argument("--maude-bin", default=str(default_maude), help="Maude executable path.")
    parser.add_argument("--results", default=str(default_results), help="JSONL result file.")
    parser.add_argument("--tag", default="", help="Optional filename/result tag.")
    parser.add_argument("--append", action="store_true", help="Append to an existing result file.")
    parser.add_argument("--no-generate", action="store_true", help="Use existing generated modules and manifest.")
    parser.add_argument("--no-summarize", action="store_true", help="Do not write CSV/Markdown summaries.")
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
    if args.cap is not None and args.cap < 1:
        raise ValueError("--cap must be >= 1")
    if not Path(args.maude_bin).exists():
        raise FileNotFoundError(f"Maude executable not found: {args.maude_bin}")

    if not args.no_generate:
        run_generator(args.maude_bin)
    manifest = load_manifest()
    jobs = select_jobs(args, manifest)
    if args.list_jobs:
        list_jobs(jobs)
        return 0
    if not jobs:
        print("[rq2] no jobs selected", file=sys.stderr)
        return 1

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    if results_path.exists() and not args.append:
        results_path.unlink()

    work_items = [(job, repeat) for repeat in range(1, args.repeat + 1) for job in jobs]
    print(
        f"[rq2] jobs={len(jobs)} repeats={args.repeat} work_items={len(work_items)} "
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
                if not bool(record.get("success")) and args.stop_on_error:
                    break
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
                futures = [
                    executor.submit(run_one, job, repeat, args, write_lock)
                    for job, repeat in work_items
                ]
                for future in concurrent.futures.as_completed(futures):
                    record = future.result()
                    records.append(record)
                    if not bool(record.get("success")) and args.stop_on_error:
                        raise RuntimeError(f"stopping after failed job {record.get('case_id')}:{record.get('mode')}")
    except KeyboardInterrupt:
        print("[rq2] interrupted", file=sys.stderr, flush=True)
        return 130

    if not args.no_summarize:
        summarize(results_path)

    hard_failures = [record for record in records if not bool(record.get("success"))]
    if hard_failures:
        print(f"[rq2] complete with hard failures={len(hard_failures)} results={args.results}", flush=True)
        return 1
    print(f"[rq2] complete results={args.results}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
