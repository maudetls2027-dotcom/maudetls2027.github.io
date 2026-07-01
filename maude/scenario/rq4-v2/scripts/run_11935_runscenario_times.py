#!/usr/bin/env python3
import argparse
import json
import subprocess
import time
from pathlib import Path


K_VALUES = [
    4999,
    9999,
    14999,
    19999,
    24999,
    29999,
    34999,
    39999,
    44999,
    49999,
    59999,
    69999,
    79999,
    89999,
    99999,
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def strip_trailing_reduction(source: Path, generated: Path) -> None:
    text = source.read_text()
    marker = "\nred runScenario("
    if marker not in text:
        raise RuntimeError(f"could not find trailing runScenario reduction in {source}")

    text = text.split(marker, 1)[0].rstrip() + "\n"
    text = text.replace(
        "load ../../requirements/8446-base.maude",
        "load ../../../../requirements/8446-base.maude",
        1,
    )
    text = text.replace("load common.maude", "load ../../common.maude", 1)
    generated.write_text(text)


def make_driver(k: int, module_path: Path, driver_path: Path) -> None:
    driver_path.write_text(
        f"""load ../generated/{module_path.name}

red size(runScenario(
  TLS-13,
  initialCWA11935,
  initConf11935 tester(N2 . SI) target(N1 . CI),
  (bdvSet{k}, wolfSSLAcceptsPskOnly11935),
  exploitCompletes11935
)) .

quit
"""
    )


def parse_maude_stats(stdout: str) -> dict:
    stats = {}
    for line in stdout.splitlines():
        if line.startswith("result "):
            stats["result"] = line.strip()
            try:
                stats["solutions"] = int(line.rsplit(":", 1)[1].strip())
            except ValueError:
                pass
        if "rewrites:" not in line:
            continue
        stats["maude_stats"] = line.strip()
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "rewrites:":
            try:
                stats["rewrites"] = int(parts[1].replace(",", ""))
            except ValueError:
                pass
        if "(" in line and "ms real" in line:
            try:
                stats["maude_real_ms"] = int(line.rsplit("(", 1)[1].split("ms real", 1)[0])
            except ValueError:
                pass
    return stats


def ensure_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def run_case(maude_bin: Path, driver: Path, timeout: int) -> dict:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [str(maude_bin), "-no-advise", str(driver)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=repo_root(),
        )
        elapsed = time.monotonic() - started
        return {
            "timeout": False,
            "returncode": proc.returncode,
            "elapsed_sec": elapsed,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            **parse_maude_stats(proc.stdout),
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        return {
            "timeout": True,
            "returncode": None,
            "elapsed_sec": elapsed,
            "stdout": ensure_text(exc.stdout),
            "stderr": ensure_text(exc.stderr),
        }


def main() -> int:
    root = repo_root()
    rq4v2 = root / "maude" / "scenario" / "rq4-v2"

    parser = argparse.ArgumentParser(
        description="Measure cve-2025-11935 runScenario time for rq4-v2 bdvSet sizes."
    )
    parser.add_argument(
        "--maude-bin",
        default=str(root / "maude" / "maude" / "maude-3.5.1" / "maude"),
        help="Maude executable path.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Per-k timeout in seconds.",
    )
    parser.add_argument(
        "--k-values",
        nargs="*",
        type=int,
        default=K_VALUES,
        help="bdvSet suffixes to run, e.g. 4999 9999 ... 99999.",
    )
    parser.add_argument(
        "--results",
        default=str(rq4v2 / "state" / "runscenario-times-11935.jsonl"),
        help="JSONL result path.",
    )
    args = parser.parse_args()

    source = rq4v2 / "cve-2025-11935.maude"
    generated_dir = rq4v2 / "state" / "generated"
    raw_dir = rq4v2 / "state" / "raw"
    generated_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    stripped = generated_dir / "cve-2025-11935.no-red.maude"
    strip_trailing_reduction(source, stripped)

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)

    maude_bin = Path(args.maude_bin)
    with results_path.open("a") as results:
        for k in args.k_values:
            driver = raw_dir / f"cve-2025-11935.bdvSet{k}.runscenario.maude"
            make_driver(k, stripped, driver)

            print(f"[rq4-v2] run cve-2025-11935 bdvSet{k}", flush=True)
            record = {
                "case": "cve-2025-11935",
                "bdv_set": f"bdvSet{k}",
                "full_size_before_trigger": k,
                "total_behavior_deviation_specs": k + 1,
                "driver": str(driver.relative_to(root)),
                "timeout_sec": args.timeout,
            }
            result = run_case(maude_bin, driver, args.timeout)

            out_path = raw_dir / f"cve-2025-11935.bdvSet{k}.runscenario.out"
            err_path = raw_dir / f"cve-2025-11935.bdvSet{k}.runscenario.err"
            out_path.write_text(result.pop("stdout"))
            err_path.write_text(result.pop("stderr"))

            record.update(result)
            record["stdout_path"] = str(out_path.relative_to(root))
            record["stderr_path"] = str(err_path.relative_to(root))
            results.write(json.dumps(record, sort_keys=True) + "\n")
            results.flush()

            status = "timeout" if record["timeout"] else f"rc={record['returncode']}"
            maude_real = record.get("maude_real_ms")
            maude_real_text = f" maude_real={maude_real / 1000:.3f}s" if maude_real is not None else ""
            print(
                f"[rq4-v2] done bdvSet{k} {status} elapsed={record['elapsed_sec']:.3f}s{maude_real_text}",
                flush=True,
            )

    print(f"[rq4-v2] results {results_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
