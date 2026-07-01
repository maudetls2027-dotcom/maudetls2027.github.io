#!/usr/bin/env python3
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


TOTAL_K_VALUES = [
    5000,
    10000,
    15000,
    20000,
    25000,
    30000,
    35000,
    40000,
    45000,
    50000,
    60000,
    70000,
    80000,
    90000,
    100000,
]


CASES = {
    "cve-2022-25638": {
        "file": "cve-2022-25638.maude",
        "module": "CVE-2022-25638",
        "protocol": "TLS-13",
        "initial_cwa": "initialCWA25638",
        "init_conf": "initConf25638",
        "cve_bss": "wolfSSLAcceptsMismatchedCV25638",
        "property": "exploitCompletes25638",
    },
    "cve-2025-11934": {
        "file": "cve-2025-11934.maude",
        "module": "CVE-2025-11934",
        "protocol": "TLS-13",
        "initial_cwa": "initialCWA11934",
        "init_conf": "initConf11934",
        "cve_bss": "wolfSSLAcceptsCV11934",
        "property": "exploitCompletes11934",
    },
    "cve-2025-11935": {
        "file": "cve-2025-11935.maude",
        "module": "CVE-2025-11935",
        "protocol": "TLS-13",
        "initial_cwa": "initialCWA11935",
        "init_conf": "initConf11935",
        "cve_bss": "wolfSSLAcceptsPskOnly11935",
        "property": "exploitCompletes11935",
    },
    "cve-2026-25834": {
        "file": "cve-2026-25834.maude",
        "module": "CVE-2026-25834",
        "protocol": "TLS-12",
        "initial_cwa": "initialCWA25834",
        "init_conf": "initConf25834",
        "cve_bss": "mbedTLSAcceptsInjectedSKE25834",
        "property": "exploitCompletes25834",
    },
    "cve-2026-3230": {
        "file": "cve-2026-3230.maude",
        "module": "CVE-2026-3230",
        "protocol": "TLS-13",
        "initial_cwa": "initialCWA3230",
        "init_conf": "initConf3230",
        "cve_bss": "wolfSSLAcceptsMissingKeyShareAfterHrr3230",
        "property": "exploitCompletes3230",
    },
}


REWRITES_RE = re.compile(
    r"rewrites:\s+([0-9,]+)\s+in\s+([0-9,]+)ms cpu\s+\(([0-9,]+)ms real\)"
)
RESULT_RE = re.compile(r"^result\s+[^:]+:\s*(.+)$")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rq4v2_dir() -> Path:
    return repo_root() / "maude" / "scenario" / "rq4-v2"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_cve_module(case_name: str) -> str:
    case = CASES[case_name]
    source = rq4v2_dir() / case["file"]
    lines = source.read_text().splitlines()
    start = None
    end = None
    for idx, line in enumerate(lines):
        if line.startswith("smod "):
            start = idx
            break
    if start is None:
        raise RuntimeError(f"could not find smod in {source}")
    for idx in range(start, len(lines)):
        if lines[idx].strip() == "endsm":
            end = idx
            break
    if end is None:
        raise RuntimeError(f"could not find endsm in {source}")
    return "\n".join(lines[start : end + 1]) + "\n"


def base_load_for(case_name: str) -> str:
    source = rq4v2_dir() / CASES[case_name]["file"]
    for line in source.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("load ../../requirements/"):
            return stripped.replace(
                "load ../../requirements/",
                "load ../../../../requirements/",
                1,
            )
    raise RuntimeError(f"could not find requirements load in {source}")


def bdv_set_for_total_k(total_k: int) -> str:
    if total_k not in TOTAL_K_VALUES:
        allowed = ", ".join(str(k) for k in TOTAL_K_VALUES)
        raise ValueError(f"unsupported k={total_k}; allowed totals: {allowed}")
    return f"bdvSet{total_k - 1}"


def make_driver(case_name: str, total_k: int, raw_dir: Path, tag: str) -> Path:
    case = CASES[case_name]
    bdv_set = bdv_set_for_total_k(total_k)
    suffix = f".{tag}" if tag else ""
    driver = raw_dir / f"{case_name}.k{total_k}{suffix}.runscenario.maude"
    runner_module = f"RQ4-V2-RUNNER-{case['module']}-K{total_k}"
    cve_module = read_cve_module(case_name)

    driver.write_text(
        f"""{base_load_for(case_name)}
load ../../common.maude

{cve_module}
smod {runner_module} is
  protecting {case['module']} .
  protecting RQ4-V2-PRE-DEFINED-BEHAVIOR-DEVIATION-SPECIFICATION .
endsm

red size(runScenario(
  {case['protocol']},
  {case['initial_cwa']},
  {case['init_conf']} tester(N2 . SI) target(N1 . CI),
  ({bdv_set}, {case['cve_bss']}),
  {case['property']}
)) .

quit
"""
    )
    return driver


def parse_stdout(stdout: str) -> dict:
    parsed = {}
    for line in stdout.splitlines():
        result_match = RESULT_RE.match(line.strip())
        if result_match:
            parsed["result"] = result_match.group(1)
            try:
                parsed["solutions"] = int(result_match.group(1))
            except ValueError:
                pass
        rewrite_match = REWRITES_RE.search(line)
        if rewrite_match:
            parsed["maude_stats"] = line.strip()
            parsed["rewrites"] = int(rewrite_match.group(1).replace(",", ""))
            parsed["maude_cpu_ms"] = int(rewrite_match.group(2).replace(",", ""))
            parsed["maude_real_ms"] = int(rewrite_match.group(3).replace(",", ""))
    return parsed


def kill_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_maude(maude_bin: Path, driver: Path, timeout: int) -> dict:
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
            **parse_stdout(stdout),
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
            **parse_stdout(stdout),
        }
    except KeyboardInterrupt:
        kill_process_group(proc)
        proc.communicate()
        raise


def run_one(case_name: str, total_k: int, args, write_lock: threading.Lock) -> dict:
    root = repo_root()
    raw_dir = rq4v2_dir() / "state" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    driver = make_driver(case_name, total_k, raw_dir, args.tag)
    suffix = f".{args.tag}" if args.tag else ""
    stdout_path = raw_dir / f"{case_name}.k{total_k}{suffix}.runscenario.out"
    stderr_path = raw_dir / f"{case_name}.k{total_k}{suffix}.runscenario.err"

    record = {
        "started_at": utc_now(),
        "case": case_name,
        "k": total_k,
        "bdv_set": bdv_set_for_total_k(total_k),
        "cve_bss": CASES[case_name]["cve_bss"],
        "property": CASES[case_name]["property"],
        "driver": str(driver.relative_to(root)),
        "timeout_sec": args.timeout,
        "maude_bin": str(args.maude_bin),
    }

    print(f"[rq4-v2] start case={case_name} k={total_k}", flush=True)
    result = run_maude(Path(args.maude_bin), driver, args.timeout)
    stdout_path.write_text(result.pop("stdout"))
    stderr_path.write_text(result.pop("stderr"))

    record.update(result)
    record["finished_at"] = utc_now()
    record["stdout_path"] = str(stdout_path.relative_to(root))
    record["stderr_path"] = str(stderr_path.relative_to(root))

    with write_lock:
        with Path(args.results).open("a") as out:
            out.write(json.dumps(record, sort_keys=True) + "\n")

    status = "timeout" if record["timeout"] else f"rc={record['returncode']}"
    maude_real = record.get("maude_real_ms")
    maude_real_text = f" maude_real={maude_real / 1000:.3f}s" if maude_real is not None else ""
    solutions = record.get("solutions")
    solutions_text = f" solutions={solutions}" if solutions is not None else ""
    print(
        f"[rq4-v2] done case={case_name} k={total_k} {status} "
        f"elapsed={record['elapsed_sec']:.3f}s{maude_real_text}{solutions_text}",
        flush=True,
    )
    return record


def select_cases(values: list[str]) -> list[str]:
    if not values or "all" in values:
        return list(CASES)
    unknown = sorted(set(values) - set(CASES))
    if unknown:
        raise ValueError(f"unknown cases: {', '.join(unknown)}")
    return values


def parse_args() -> argparse.Namespace:
    root = repo_root()
    default_maude = root / "maude" / "maude" / "maude-3.5.1" / "maude"
    default_results = rq4v2_dir() / "state" / "runscenario-matrix.jsonl"

    parser = argparse.ArgumentParser(
        description="Run RQ4-v2 runScenario timing experiments for selected CVEs and k values."
    )
    parser.add_argument(
        "--case",
        nargs="+",
        default=["all"],
        help=f"Cases to run, or all. Available: {', '.join(CASES)}",
    )
    parser.add_argument(
        "--k",
        nargs="+",
        type=int,
        default=TOTAL_K_VALUES,
        help="Total full-set sizes: 5000 10000 ... 100000.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Number of parallel Maude processes.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=86400,
        help="Per-case timeout in seconds.",
    )
    parser.add_argument(
        "--maude-bin",
        default=str(default_maude),
        help="Maude executable path.",
    )
    parser.add_argument(
        "--results",
        default=str(default_results),
        help="JSONL result file.",
    )
    parser.add_argument(
        "--tag",
        default="",
        help="Optional filename tag, useful for repeated server runs.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.maude_bin = str(Path(args.maude_bin).expanduser())
    args.results = str(Path(args.results).expanduser())

    cases = select_cases(args.case)
    for k in args.k:
        bdv_set_for_total_k(k)
    if args.jobs < 1:
        raise ValueError("--jobs must be >= 1")

    Path(args.results).parent.mkdir(parents=True, exist_ok=True)
    combinations = [(case_name, k) for case_name in cases for k in args.k]
    print(
        f"[rq4-v2] combinations={len(combinations)} jobs={args.jobs} "
        f"results={args.results}",
        flush=True,
    )

    write_lock = threading.Lock()
    try:
        if args.jobs == 1:
            for case_name, k in combinations:
                run_one(case_name, k, args, write_lock)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
                futures = [
                    executor.submit(run_one, case_name, k, args, write_lock)
                    for case_name, k in combinations
                ]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
    except KeyboardInterrupt:
        print("[rq4-v2] interrupted", file=sys.stderr, flush=True)
        return 130

    print(f"[rq4-v2] complete results={args.results}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
