#!/usr/bin/env python3
"""Run RQ4 strategy-guided prefix-count experiments.

All generated drivers, raw outputs, and parsed results stay under
maude/scenario/rq4/state.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCRIPT = Path(__file__).resolve()
RQ4_DIR = SCRIPT.parents[1]
REPO = SCRIPT.parents[4]
STATE_DIR = RQ4_DIR / "state"
RAW_DIR = STATE_DIR / "raw"
GEN_DIR = STATE_DIR / "generated"
RESULTS_JSONL = STATE_DIR / "results.jsonl"
SUMMARY_JSON = STATE_DIR / "summary.json"
DEFAULT_MAUDE = Path(os.environ.get("MAUDE_BIN", str(REPO / "maude" / "maude" / "maude-3.5.1" / "maude")))
PHASES = ("all", "specific", "noCheck", "closed", "time")
CURRENT_FULL_SAMPLE_METHOD = "prefix"
CURRENT_FULL_SEED: int | None = None
CURRENT_FULL_SOURCES: tuple[str, ...] = ("5246-core", "8446-core", "hrr", "psk")


@dataclass(frozen=True)
class Case:
    case: str
    wrapper: str
    driver_module: str
    protocol: str
    initial_cwa: str
    init_conf: str
    scoped_bss: str
    specific_bss: str
    no_check_bss: str
    common_bss: str
    all_behavior_ap: str
    specific_entry: str
    trigger: str
    bypass: str
    goal: str
    common_sources: tuple[str, ...]


CASES: dict[str, Case] = {
    "cve-2026-25834": Case(
        case="cve-2026-25834",
        wrapper="cve-2026-25834.maude",
        driver_module="RQ4-DRIVER-25834",
        protocol="TLS-12",
        initial_cwa="initialCWA25834",
        init_conf="initConf25834 tester(N2 . SI) target(N1 . CI)",
        scoped_bss="scoped25834",
        specific_bss="specificBss25834",
        no_check_bss="noCheckBss25834",
        common_bss="rq4Common25834",
        all_behavior_ap="allBehaviorDVSpec25834",
        specific_entry=(
            "{'cve25834-use-unoffered-ske-sigalg, "
            "ruleLabel('buildServerKeyExchangeV2), "
            "setM(#server-key-exchange-algorithm, mv[{ecdsa,sha256}])}"
        ),
        trigger="trigger25834",
        bypass="bypass25834",
        goal="goal25834",
        common_sources=("5246-core",),
    ),
    "cve-2026-3230": Case(
        case="cve-2026-3230",
        wrapper="cve-2026-3230.maude",
        driver_module="RQ4-DRIVER-3230",
        protocol="TLS-13",
        initial_cwa="initialCWA3230",
        init_conf="initConf3230 tester(N2 . SI) target(N1 . CI)",
        scoped_bss="scoped3230",
        specific_bss="specificBss3230",
        no_check_bss="noCheckBss3230",
        common_bss="rq4Common3230",
        all_behavior_ap="allBehaviorDVSpec3230",
        specific_entry=(
            "{'cve3230-omit-hrr-server-key-share, "
            "ruleLabel('buildServerHelloV3) and appliedNode(server), "
            "remove(#key-shares)}"
        ),
        trigger="trigger3230",
        bypass="bypass3230",
        goal="goal3230",
        common_sources=("8446-core", "hrr"),
    ),
    "cve-2025-11935": Case(
        case="cve-2025-11935",
        wrapper="cve-2025-11935.maude",
        driver_module="RQ4-DRIVER-11935",
        protocol="TLS-13",
        initial_cwa="initialCWA11935",
        init_conf="initConf11935 tester(N2 . SI) target(N1 . CI)",
        scoped_bss="scoped11935",
        specific_bss="specificBss11935",
        no_check_bss="noCheckBss11935",
        common_bss="rq4Common11935",
        all_behavior_ap="allBehaviorDVSpec11935",
        specific_entry=(
            "{'cve11935-omit-server-key-share, "
            "ruleLabel('buildServerHelloV3) and appliedNode(server) and "
            "featureMap(@reconnectInProgress |-> av[true]), "
            "remove(#key-shares)}"
        ),
        trigger="trigger11935",
        bypass="bypass11935",
        goal="goal11935",
        common_sources=("8446-core", "psk"),
    ),
    "cve-2025-11934": Case(
        case="cve-2025-11934",
        wrapper="cve-2025-11934.maude",
        driver_module="RQ4-DRIVER-11934",
        protocol="TLS-13",
        initial_cwa="initialCWA11934",
        init_conf="initConf11934 tester(N2 . SI) target(N1 . CI)",
        scoped_bss="scoped11934",
        specific_bss="specificBss11934",
        no_check_bss="noCheckBss11934",
        common_bss="rq4Common11934",
        all_behavior_ap="allBehaviorDVSpec11934",
        specific_entry=(
            "{'cve11934-use-ecdsa-sha256-cv, "
            "ruleLabel('buildServerCertificateV3), "
            "setF(@selectedSignatureAlgorithms, av[{ecdsa,sha256}])}"
        ),
        trigger="trigger11934",
        bypass="bypass11934",
        goal="goal11934",
        common_sources=("8446-core",),
    ),
}


SOURCE_FILES = {
    "5246-core": RQ4_DIR.parent / "rfc" / "5246-core.maude",
    "8446-core": RQ4_DIR.parent / "rfc" / "8446-core.maude",
    "hrr": RQ4_DIR.parent / "rfc" / "hrr.maude",
    "psk": RQ4_DIR.parent / "rfc" / "psk.maude",
}

# RQ4 full-k uses a global RFC deviation pool for every CVE:
# one CVE-specific trigger plus k-1 irrelevant entries sampled from this pool.
# The pool is configured with --full-sources.
DEFAULT_FULL_SOURCES = ("5246-core", "8446-core", "hrr", "psk")


REDUCTION_RE = re.compile(
    r"rewrites:\s+(?P<rewrites>\d+)\s+in\s+(?P<cpu>\d+)ms cpu\s+\((?P<real>\d+)ms real\).*?"
    r"result Bool:\s+(?P<result>true|false)",
    re.S,
)


def timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def split_set_entries(text: str) -> list[str]:
    entries: list[str] = []
    start = 0
    depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = {")", "]", "}"}
    for idx, char in enumerate(text):
        if char in pairs:
            depth += 1
        elif char in closing:
            depth -= 1
            if depth < 0:
                raise ValueError(f"unbalanced set term near: {text}")
        elif char == "," and depth == 0:
            entry = text[start:idx].strip()
            if entry:
                entries.append(entry)
            start = idx + 1
    tail = text[start:].strip()
    if tail:
        entries.append(tail)
    if depth != 0:
        raise ValueError(f"unbalanced set term near: {text}")
    return entries


def behavior_entry_label(entry: str) -> str:
    match = re.match(r"\{\s*'([A-Za-z0-9_-]+)\s*,", entry)
    if not match:
        raise ValueError(f"could not find BehaviorDVSpec label in: {entry}")
    return match.group(1)


def relabel_behavior_entry(entry: str, label: str) -> str:
    behavior_entry_label(entry)
    return re.sub(r"\{\s*'([A-Za-z0-9_-]+)\s*,", "{'" + label + ",", entry, count=1)


def namespace_behavior_entry(entry: str, namespace: str) -> tuple[str, str]:
    label = behavior_entry_label(entry)
    namespaced = f"{namespace}-{label}"
    return relabel_behavior_entry(entry, namespaced), namespaced


def extract_behavior_entries(path: Path, namespace: str) -> list[tuple[str, str]]:
    lines = path.read_text().splitlines()
    entries: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = re.match(r"\s*eq\s+behaviorDeviationSpecification\d+\s*=\s*(.*)$", line)
        if not match:
            i += 1
            continue

        collected = [match.group(1)]
        while not collected[-1].rstrip().endswith("."):
            i += 1
            if i >= len(lines):
                raise ValueError(f"unterminated behaviorDeviationSpecification equation in {path}")
            collected.append(lines[i])

        text = "\n".join(collected).strip()
        if not text.endswith("."):
            raise ValueError(f"malformed behaviorDeviationSpecification equation in {path}")
        text = text[:-1].strip()

        if text != "empty":
            entries.extend(namespace_behavior_entry(entry, namespace) for entry in split_set_entries(text))
        i += 1
    return entries


def make_set_expr(terms: Iterable[str]) -> str:
    terms = [term for term in terms if term and term != "empty"]
    if not terms:
        return "empty"
    return ",\n     ".join(terms)


def compact_term(term: str) -> str:
    return re.sub(r"\s+", " ", term).strip()


def limit_suffix(full_limit: int | None) -> str:
    if full_limit is None:
        return ""
    suffix = f"Limit{full_limit}"
    if CURRENT_FULL_SAMPLE_METHOD == "random":
        suffix += f"Seed{CURRENT_FULL_SEED}"
    return suffix


def full_file_key(full_limit: int | None) -> str:
    if full_limit is None:
        return "default"
    if CURRENT_FULL_SAMPLE_METHOD == "random":
        source_key = "-".join(source.replace("-", "") for source in CURRENT_FULL_SOURCES)
        return f"limit-{full_limit}-seed-{CURRENT_FULL_SEED}-{source_key}"
    return f"limit-{full_limit}"


def common_bss_name(case: Case, full_limit: int | None) -> str:
    return case.common_bss + limit_suffix(full_limit)


def full_bss_name(case: Case, full_limit: int | None) -> str:
    return case.common_bss + "Full" + limit_suffix(full_limit)


def all_behavior_ap_name(case: Case, full_limit: int | None) -> str:
    return case.all_behavior_ap + limit_suffix(full_limit)


def full_behavior_label(case: Case, full_limit: int | None) -> str:
    return all_behavior_ap_name(case, full_limit)


def result_variant_name(variant: str, full_limit: int | None) -> str:
    if variant == "full" and full_limit is not None:
        name = f"full-{full_limit}"
        if CURRENT_FULL_SAMPLE_METHOD == "random":
            name += f"-seed-{CURRENT_FULL_SEED}"
        return name
    return variant


def irrelevant_behavior_limit(full_limit: int | None) -> int | None:
    if full_limit is None:
        return None
    return max(full_limit - 1, 0)


def select_irrelevant_entries(
    entries: list[tuple[str, str]],
    full_limit: int | None,
) -> list[tuple[str, str]]:
    irrelevant_limit = irrelevant_behavior_limit(full_limit)
    if irrelevant_limit is None:
        return entries
    if irrelevant_limit >= len(entries):
        return entries
    if CURRENT_FULL_SAMPLE_METHOD == "prefix":
        return entries[:irrelevant_limit]
    if CURRENT_FULL_SAMPLE_METHOD == "random":
        assert CURRENT_FULL_SEED is not None
        rng = random.Random(CURRENT_FULL_SEED)
        indices = sorted(rng.sample(range(len(entries)), irrelevant_limit))
        return [entries[index] for index in indices]
    raise ValueError(f"unknown full sample method {CURRENT_FULL_SAMPLE_METHOD}")


def generated_common_path(cases: Iterable[Case], full_limit: int | None) -> Path:
    case_list = list(cases)
    if not case_list:
        raise ValueError("no cases selected")
    case_key = "all" if len(case_list) > 1 else case_list[0].case
    limit_key = full_file_key(full_limit)
    return GEN_DIR / f"rq4-common-generated.{case_key}.{limit_key}.maude"


def generate_common(cases: Iterable[Case], full_limit: int | None) -> Path:
    case_list = list(cases)
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    chunks: list[str] = [
        "load ../../common.maude",
        "",
        "smod RQ4-COMMON-GENERATED is",
        "  protecting RQ4-COMMON .",
        "",
    ]

    for case in case_list:
        entries: list[tuple[str, str]] = []
        for source in CURRENT_FULL_SOURCES:
            entries.extend(extract_behavior_entries(SOURCE_FILES[source], f"rq4-{source}"))
        entries = select_irrelevant_entries(entries, full_limit)
        public_label = full_behavior_label(case, full_limit)
        full_entries = [relabel_behavior_entry(case.specific_entry, public_label)]
        full_entries.extend(relabel_behavior_entry(entry, public_label) for entry, _ in entries)
        if full_limit is not None:
            variant = result_variant_name("full", full_limit)
            print(
                "[rq4] "
                f"full-sample case={case.case} variant={variant} "
                f"method={CURRENT_FULL_SAMPLE_METHOD} seed={CURRENT_FULL_SEED} "
                f"sources={' '.join(CURRENT_FULL_SOURCES)} "
                f"selected_irrelevant={len(entries)}",
                flush=True,
            )
            print(
                "[rq4] "
                f"full-sample case={case.case} variant={variant} "
                f"included_trigger_bss={case.specific_bss} included_trigger_ap={case.trigger} "
                f"public_label='{public_label}'",
                flush=True,
            )
            for idx, (entry, label) in enumerate(entries, start=1):
                print(
                    "[rq4] "
                    f"full-sample case={case.case} variant={variant} "
                    f"irrelevant[{idx}] label='{label} spec={compact_term(entry)}",
                    flush=True,
                )
        chunks.append(
            f"  --- full sample method: {CURRENT_FULL_SAMPLE_METHOD}; "
            f"seed: {CURRENT_FULL_SEED}; sources: {' '.join(CURRENT_FULL_SOURCES)}; "
            f"selected irrelevant entries: {len(entries)}"
        )
        chunks.append(f"  op {common_bss_name(case, full_limit)} : -> Set{{BehaviorDVSpec}} .")
        chunks.append(f"  eq {common_bss_name(case, full_limit)} =")
        chunks.append("     " + make_set_expr(entry for entry, _ in entries) + " .")
        chunks.append("")
        chunks.append(f"  op {full_bss_name(case, full_limit)} : -> Set{{BehaviorDVSpec}} .")
        chunks.append(f"  eq {full_bss_name(case, full_limit)} =")
        chunks.append("     " + make_set_expr(full_entries) + " .")
        chunks.append("")
        chunks.append(f"  op {all_behavior_ap_name(case, full_limit)} : -> ActionProposition .")
        chunks.append(f"  eq {all_behavior_ap_name(case, full_limit)} =")
        chunks.append(f"     ruleLabel('{public_label}) .")
        chunks.append("")

    chunks.append("endsm")
    path = generated_common_path(case_list, full_limit)
    path.write_text("\n".join(chunks) + "\n")
    return path


def seq_property(parts: list[str]) -> str:
    if not parts:
        return "anyStep"
    return " ; ".join(parts)


def first_ap(case: Case, variant: str, full_limit: int | None) -> str:
    if variant == "scoped":
        return case.trigger
    if variant == "full":
        return all_behavior_ap_name(case, full_limit)
    raise ValueError(f"unknown variant {variant}")


def first_phase_name(variant: str) -> str:
    if variant == "scoped":
        return "specific"
    if variant == "full":
        return "all"
    raise ValueError(f"unknown variant {variant}")


def first_property(case: Case, variant: str, pre: int, full_limit: int | None) -> str:
    return seq_property(["anyStep"] * pre + [first_ap(case, variant, full_limit)])


def no_check_property(case: Case, variant: str, pre: int, mid: int, full_limit: int | None) -> str:
    return seq_property(
        ["anyStep"] * pre + [first_ap(case, variant, full_limit)] + ["anyStep"] * mid + [case.bypass]
    )


def closed_property(case: Case, variant: str, pre: int, mid: int, post: int, full_limit: int | None) -> str:
    return seq_property(
        ["anyStep"] * pre
        + [first_ap(case, variant, full_limit)]
        + ["anyStep"] * mid
        + [case.bypass]
        + ["anyStep"] * post
        + [case.goal]
    )


def time_property(case: Case, variant: str, full_limit: int | None) -> str:
    return seq_property(
        [
            "(anyStep *)",
            first_ap(case, variant, full_limit),
            "(anyStep *)",
            case.bypass,
            "(anyStep *)",
            case.goal,
        ]
    )


def bss_expr(case: Case, variant: str, full_limit: int | None) -> str:
    if variant == "scoped":
        return f"({case.specific_bss}, {case.no_check_bss})"
    if variant == "full":
        return f"({full_bss_name(case, full_limit)}, {case.no_check_bss})"
    raise ValueError(f"unknown variant {variant}")


def reduction_text(
    case: Case,
    variant: str,
    prop: str,
    solution_index: int,
    full_limit: int | None,
) -> str:
    return (
        "red rq4HasSolution("
        f"{case.protocol}, "
        f"{case.initial_cwa}, "
        f"{case.init_conf}, "
        f"{bss_expr(case, variant, full_limit)}, "
        f"({prop}), "
        f"{solution_index}"
        ") ."
    )


def driver_lines(
    case: Case,
    variant: str,
    reductions: list[str],
    generated_common: Path | None,
) -> list[str]:
    lines = [f"load ../../{case.wrapper}"]
    protects = [f"  protecting RQ4-CVE-{case.case.upper().replace('CVE-', '')} ."]
    if variant == "full":
        if generated_common is None:
            raise ValueError("full variant requires generated_common")
        lines.append(f"load ../generated/{generated_common.name}")
        protects.insert(0, "  protecting RQ4-COMMON-GENERATED .")
    lines.extend(
        [
            "",
            f"smod {case.driver_module} is",
            *protects,
            "endsm",
            "",
            *reductions,
            "quit",
            "",
        ]
    )
    return lines


def write_driver(
    case: Case,
    variant: str,
    prop: str,
    solution_index: int,
    tag: str,
    full_limit: int | None,
    generated_common: Path | None,
) -> Path:
    safe_tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", tag)
    raw_variant = result_variant_name(variant, full_limit)
    path = RAW_DIR / f"{case.case}.{raw_variant}.{safe_tag}.maude"
    reduction = reduction_text(case, variant, prop, solution_index, full_limit)
    path.write_text("\n".join(driver_lines(case, variant, [reduction], generated_common)))
    return path


def write_driver_batch(
    case: Case,
    variant: str,
    prop: str,
    solution_indices: list[int],
    tag: str,
    full_limit: int | None,
    generated_common: Path | None,
) -> Path:
    safe_tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", tag)
    raw_variant = result_variant_name(variant, full_limit)
    path = RAW_DIR / f"{case.case}.{raw_variant}.{safe_tag}.maude"
    reductions = [
        reduction_text(case, variant, prop, solution_index, full_limit)
        for solution_index in solution_indices
    ]
    path.write_text("\n".join(driver_lines(case, variant, reductions, generated_common)))
    return path


def parse_results(stdout: str) -> list[dict[str, int | bool]]:
    results: list[dict[str, int | bool]] = []
    for match in REDUCTION_RE.finditer(stdout):
        results.append(
            {
                "rewrites": int(match.group("rewrites")),
                "cpu_ms": int(match.group("cpu")),
                "real_ms": int(match.group("real")),
                "has_solution": match.group("result") == "true",
            }
        )
    return results


def run_property(
    *,
    maude: Path,
    case: Case,
    variant: str,
    phase: str,
    depths: tuple[int, ...],
    prop: str,
    cap: int,
    timeout: int,
    count_method: str,
    probe_mode: str,
    full_limit: int | None,
    generated_common: Path | None,
) -> dict:
    tag = phase + "." + ".".join(str(d) for d in depths)
    started = time.monotonic()
    driver_paths: list[str] = []
    raw_stdout_paths: list[str] = []
    raw_stderr_paths: list[str] = []
    total_rewrites = 0
    total_cpu_ms = 0
    total_real_ms = 0

    def row(
        *,
        solution_count: int,
        lower_bound: int,
        complete: bool,
        capped: bool,
        timed_out: bool,
        error: str | None,
    ) -> dict:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        driver = driver_paths[-1] if driver_paths else ""
        raw_stdout = raw_stdout_paths[-1] if raw_stdout_paths else ""
        raw_stderr = raw_stderr_paths[-1] if raw_stderr_paths else ""
        return {
            "case": case.case,
            "variant": result_variant_name(variant, full_limit),
            "phase": phase,
            "depths": depths,
            "property": prop,
            "solution_count": solution_count,
            "lower_bound": lower_bound,
            "complete": complete,
            "capped": capped,
            "timeout": timed_out,
            "elapsed_ms": elapsed_ms,
            "maude_rewrites_sum": total_rewrites,
            "maude_cpu_ms_sum": total_cpu_ms,
            "maude_real_ms_sum": total_real_ms,
            "driver": driver,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "drivers": driver_paths,
            "raw_stdouts": raw_stdout_paths,
            "raw_stderrs": raw_stderr_paths,
            "error": error,
        }

    def query_solution(solution_index: int) -> bool | dict:
        nonlocal total_rewrites, total_cpu_ms, total_real_ms
        if count_method == "binary":
            depth_text = ",".join(str(depth) for depth in depths)
            depth_text = f"({depth_text})" if depth_text else "()"
            print(
                "[rq4] "
                f"{case.case} {result_variant_name(variant, full_limit)} {phase}{depth_text} "
                f"probe n={solution_index}",
                flush=True,
            )
        driver = write_driver(
            case,
            variant,
            prop,
            solution_index,
            f"{tag}.n{solution_index}",
            full_limit,
            generated_common,
        )
        raw_out = driver.with_suffix(".out")
        raw_err = driver.with_suffix(".err")
        driver_paths.append(str(driver.relative_to(RQ4_DIR)))
        raw_stdout_paths.append(str(raw_out.relative_to(RQ4_DIR)))
        raw_stderr_paths.append(str(raw_err.relative_to(RQ4_DIR)))

        try:
            completed = subprocess.run(
                [str(maude), "-no-advise", str(driver)],
                cwd=RQ4_DIR,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            raw_out.write_text(completed.stdout)
            raw_err.write_text(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            raw_out.write_text(timeout_text(exc.stdout))
            raw_err.write_text(timeout_text(exc.stderr) or "timeout")
            return row(
                solution_count=solution_index,
                lower_bound=solution_index,
                complete=False,
                capped=False,
                timed_out=True,
                error=f"timeout at solution index {solution_index}",
            )

        parsed = parse_results(completed.stdout)
        if parsed:
            total_rewrites += int(parsed[0]["rewrites"])
            total_cpu_ms += int(parsed[0]["cpu_ms"])
            total_real_ms += int(parsed[0]["real_ms"])

        if completed.returncode != 0:
            return row(
                solution_count=solution_index,
                lower_bound=solution_index,
                complete=False,
                capped=False,
                timed_out=False,
                error=f"maude exit {completed.returncode} at solution index {solution_index}",
            )
        if len(parsed) != 1:
            return row(
                solution_count=solution_index,
                lower_bound=solution_index,
                complete=False,
                capped=False,
                timed_out=False,
                error=f"parsed {len(parsed)} results, expected 1 at solution index {solution_index}",
        )
        return bool(parsed[0]["has_solution"])

    def query_solutions(solution_indices: list[int]) -> list[bool] | dict:
        nonlocal total_rewrites, total_cpu_ms, total_real_ms
        if not solution_indices:
            return []
        if len(solution_indices) == 1:
            result = query_solution(solution_indices[0])
            return result if isinstance(result, dict) else [result]

        depth_text = ",".join(str(depth) for depth in depths)
        depth_text = f"({depth_text})" if depth_text else "()"
        print(
            "[rq4] "
            f"{case.case} {result_variant_name(variant, full_limit)} {phase}{depth_text} "
            f"probe batch n={solution_indices[0]}..{solution_indices[-1]} count={len(solution_indices)}",
            flush=True,
        )
        driver = write_driver_batch(
            case,
            variant,
            prop,
            solution_indices,
            f"{tag}.batch{len(solution_indices)}.{solution_indices[0]}-{solution_indices[-1]}",
            full_limit,
            generated_common,
        )
        raw_out = driver.with_suffix(".out")
        raw_err = driver.with_suffix(".err")
        driver_paths.append(str(driver.relative_to(RQ4_DIR)))
        raw_stdout_paths.append(str(raw_out.relative_to(RQ4_DIR)))
        raw_stderr_paths.append(str(raw_err.relative_to(RQ4_DIR)))

        try:
            completed = subprocess.run(
                [str(maude), "-no-advise", str(driver)],
                cwd=RQ4_DIR,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            raw_out.write_text(completed.stdout)
            raw_err.write_text(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            raw_out.write_text(timeout_text(exc.stdout))
            raw_err.write_text(timeout_text(exc.stderr) or "timeout")
            return row(
                solution_count=0,
                lower_bound=0,
                complete=False,
                capped=False,
                timed_out=True,
                error=(
                    "timeout at solution indices "
                    f"{solution_indices[0]}..{solution_indices[-1]}"
                ),
            )

        parsed = parse_results(completed.stdout)
        for result in parsed:
            total_rewrites += int(result["rewrites"])
            total_cpu_ms += int(result["cpu_ms"])
            total_real_ms += int(result["real_ms"])

        if completed.returncode != 0:
            return row(
                solution_count=0,
                lower_bound=0,
                complete=False,
                capped=False,
                timed_out=False,
                error=(
                    f"maude exit {completed.returncode} at solution indices "
                    f"{solution_indices[0]}..{solution_indices[-1]}"
                ),
            )
        if len(parsed) != len(solution_indices):
            return row(
                solution_count=0,
                lower_bound=0,
                complete=False,
                capped=False,
                timed_out=False,
                error=(
                    f"parsed {len(parsed)} results, expected {len(solution_indices)} "
                    f"at solution indices {solution_indices[0]}..{solution_indices[-1]}"
                ),
            )
        return [bool(result["has_solution"]) for result in parsed]

    if count_method == "linear":
        for solution_index in range(cap + 1):
            result = query_solution(solution_index)
            if isinstance(result, dict):
                return result
            if not result:
                return row(
                    solution_count=solution_index,
                    lower_bound=solution_index,
                    complete=True,
                    capped=False,
                    timed_out=False,
                    error=None,
                )

        return row(
            solution_count=cap + 1,
            lower_bound=cap + 1,
            complete=False,
            capped=True,
            timed_out=False,
            error=f"solution cap {cap} reached",
        )

    if count_method != "binary":
        raise ValueError(f"unknown count method {count_method}")

    if probe_mode == "batch":
        probes = [0]
        if cap > 0:
            probe = 1
            while probe <= cap:
                probes.append(probe)
                probe *= 2
            if probes[-1] != cap:
                probes.append(cap)

        batch = query_solutions(probes)
        if isinstance(batch, dict):
            return batch
        first_false: int | None = None
        last_true = -1
        for solution_index, has_solution in zip(probes, batch):
            if has_solution:
                last_true = solution_index
            else:
                first_false = solution_index
                break

        if first_false == 0:
            return row(
                solution_count=0,
                lower_bound=0,
                complete=True,
                capped=False,
                timed_out=False,
                error=None,
            )
        if first_false is None:
            return row(
                solution_count=cap + 1,
                lower_bound=cap + 1,
                complete=False,
                capped=True,
                timed_out=False,
                error=f"solution cap {cap} reached",
            )
        if cap == 0:
            return row(
                solution_count=1,
                lower_bound=1,
                complete=False,
                capped=True,
                timed_out=False,
                error=f"solution cap {cap} reached",
            )
        low = last_true + 1
        high = first_false
    else:
        first = query_solution(0)
        if isinstance(first, dict):
            return first
        if not first:
            return row(
                solution_count=0,
                lower_bound=0,
                complete=True,
                capped=False,
                timed_out=False,
                error=None,
            )
        if cap == 0:
            return row(
                solution_count=1,
                lower_bound=1,
                complete=False,
                capped=True,
                timed_out=False,
                error=f"solution cap {cap} reached",
            )

        last_true = 0
        probe = 1
        while probe <= cap:
            result = query_solution(probe)
            if isinstance(result, dict):
                lower_bound = last_true + 1
                result["solution_count"] = lower_bound
                result["lower_bound"] = lower_bound
                return result
            if not result:
                low = last_true + 1
                high = probe
                break
            last_true = probe
            probe *= 2
        else:
            if last_true == cap:
                return row(
                    solution_count=cap + 1,
                    lower_bound=cap + 1,
                    complete=False,
                    capped=True,
                    timed_out=False,
                    error=f"solution cap {cap} reached",
                )

            result = query_solution(cap)
            if isinstance(result, dict):
                lower_bound = last_true + 1
                result["solution_count"] = lower_bound
                result["lower_bound"] = lower_bound
                return result
            if result:
                return row(
                    solution_count=cap + 1,
                    lower_bound=cap + 1,
                    complete=False,
                    capped=True,
                    timed_out=False,
                    error=f"solution cap {cap} reached",
                )
            low = last_true + 1
            high = cap

    if low == high:
        return row(
            solution_count=low,
            lower_bound=low,
            complete=True,
            capped=False,
            timed_out=False,
            error=None,
        )

    while low < high:
        mid = (low + high) // 2
        result = query_solution(mid)
        if isinstance(result, dict):
            result["solution_count"] = low
            result["lower_bound"] = low
            return result
        if result:
            low = mid + 1
        else:
            high = mid

    return row(
        solution_count=low,
        lower_bound=low,
        complete=True,
        capped=False,
        timed_out=False,
        error=None,
    )


def print_row_progress(row: dict) -> None:
    depth_text = ",".join(str(depth) for depth in row["depths"])
    depth_text = f"({depth_text})" if depth_text else "()"
    print(
        "[rq4] "
        f"{row['case']} {row['variant']} {row['phase']}{depth_text} "
        f"count={row['solution_count']} complete={row['complete']} "
        f"capped={row['capped']} timeout={row['timeout']} "
        f"elapsed_ms={row['elapsed_ms']}",
        flush=True,
    )


def row_is_incomplete(row: dict) -> bool:
    return bool(row.get("timeout") or row.get("capped") or row.get("error") or not row.get("complete"))


def append_row(row: dict) -> None:
    with RESULTS_JSONL.open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def load_result_rows(path: Path = RESULTS_JSONL) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def run_case_variant(
    args: argparse.Namespace,
    case: Case,
    variant: str,
    maude: Path,
    generated_common: Path | None,
) -> list[dict]:
    rows: list[dict] = []

    first_depths: list[int] = []
    zero_streak = 0
    seen_positive = False
    for pre in range(args.max_pre + 1):
        row = run_property(
            maude=maude,
            case=case,
            variant=variant,
            phase=first_phase_name(variant),
            depths=(pre,),
            prop=first_property(case, variant, pre, args.full_limit if variant == "full" else None),
            cap=args.solution_cap,
            timeout=args.timeout,
            count_method=args.count_method,
            probe_mode=args.probe_mode,
            full_limit=args.full_limit if variant == "full" else None,
            generated_common=generated_common,
        )
        rows.append(row)
        append_row(row)
        print_row_progress(row)
        if row_is_incomplete(row):
            return rows
        if row["solution_count"] and not row["timeout"]:
            first_depths.append(pre)
            zero_streak = 0
            seen_positive = True
        else:
            zero_streak += 1
            # In full-K scans, irrelevant deviations can make early depths positive
            # while the CVE trigger appears later, e.g., all(0)>0 and all(4)>0.
            # Keep scanning the first phase through max-pre so sparse trigger depths
            # are not silently skipped.
            if (
                variant != "full"
                and args.zero_streak > 0
                and seen_positive
                and zero_streak >= args.zero_streak
            ):
                break

    no_check_depths: list[tuple[int, int]] = []
    for pre in first_depths:
        zero_streak = 0
        seen_positive = False
        for mid in range(args.max_mid + 1):
            row = run_property(
                maude=maude,
                case=case,
                variant=variant,
                phase="noCheck",
                depths=(pre, mid),
                prop=no_check_property(case, variant, pre, mid, args.full_limit if variant == "full" else None),
                cap=args.solution_cap,
                timeout=args.timeout,
                count_method=args.count_method,
                probe_mode=args.probe_mode,
                full_limit=args.full_limit if variant == "full" else None,
                generated_common=generated_common,
            )
            rows.append(row)
            append_row(row)
            print_row_progress(row)
            if row_is_incomplete(row):
                return rows
            if row["solution_count"] and not row["timeout"]:
                no_check_depths.append((pre, mid))
                zero_streak = 0
                seen_positive = True
            else:
                zero_streak += 1
                if args.zero_streak > 0 and seen_positive and zero_streak >= args.zero_streak:
                    break

    for pre, mid in no_check_depths:
        zero_streak = 0
        seen_positive = False
        for post in range(args.max_post + 1):
            row = run_property(
                maude=maude,
                case=case,
                variant=variant,
                phase="closed",
                depths=(pre, mid, post),
                prop=closed_property(case, variant, pre, mid, post, args.full_limit if variant == "full" else None),
                cap=args.solution_cap,
                timeout=args.timeout,
                count_method=args.count_method,
                probe_mode=args.probe_mode,
                full_limit=args.full_limit if variant == "full" else None,
                generated_common=generated_common,
            )
            rows.append(row)
            append_row(row)
            print_row_progress(row)
            if row_is_incomplete(row):
                return rows
            if row["solution_count"] and not row["timeout"]:
                zero_streak = 0
                seen_positive = True
            else:
                zero_streak += 1
                if args.zero_streak > 0 and seen_positive and zero_streak >= args.zero_streak:
                    break

    return rows


def run_case_variant_fixed(
    args: argparse.Namespace,
    case: Case,
    variant: str,
    maude: Path,
    depths_by_phase: dict[str, list[list[int]]],
    generated_common: Path | None,
) -> list[dict]:
    rows: list[dict] = []

    first_depth_key = first_phase_name(variant)
    for depths in depths_by_phase.get(first_depth_key, []):
        if len(depths) != 1:
            continue
        pre = int(depths[0])
        row = run_property(
            maude=maude,
            case=case,
            variant=variant,
            phase=first_depth_key,
            depths=(pre,),
            prop=first_property(case, variant, pre, args.full_limit if variant == "full" else None),
            cap=args.solution_cap,
            timeout=args.timeout,
            count_method=args.count_method,
            probe_mode=args.probe_mode,
            full_limit=args.full_limit if variant == "full" else None,
            generated_common=generated_common,
        )
        rows.append(row)
        append_row(row)
        print_row_progress(row)
        if row_is_incomplete(row):
            return rows

    for depths in depths_by_phase.get("noCheck", []):
        if len(depths) != 2:
            continue
        pre, mid = (int(depths[0]), int(depths[1]))
        row = run_property(
            maude=maude,
            case=case,
            variant=variant,
            phase="noCheck",
            depths=(pre, mid),
            prop=no_check_property(case, variant, pre, mid, args.full_limit if variant == "full" else None),
            cap=args.solution_cap,
            timeout=args.timeout,
            count_method=args.count_method,
            probe_mode=args.probe_mode,
            full_limit=args.full_limit if variant == "full" else None,
            generated_common=generated_common,
        )
        rows.append(row)
        append_row(row)
        print_row_progress(row)
        if row_is_incomplete(row):
            return rows

    for depths in depths_by_phase.get("closed", []):
        if len(depths) != 3:
            continue
        pre, mid, post = (int(depths[0]), int(depths[1]), int(depths[2]))
        row = run_property(
            maude=maude,
            case=case,
            variant=variant,
            phase="closed",
            depths=(pre, mid, post),
            prop=closed_property(case, variant, pre, mid, post, args.full_limit if variant == "full" else None),
            cap=args.solution_cap,
            timeout=args.timeout,
            count_method=args.count_method,
            probe_mode=args.probe_mode,
            full_limit=args.full_limit if variant == "full" else None,
            generated_common=generated_common,
        )
        rows.append(row)
        append_row(row)
        print_row_progress(row)
        if row_is_incomplete(row):
            return rows

    return rows


def run_case_variant_time(
    args: argparse.Namespace,
    case: Case,
    variant: str,
    maude: Path,
    generated_common: Path | None,
) -> list[dict]:
    row = run_property(
        maude=maude,
        case=case,
        variant=variant,
        phase="time",
        depths=(),
        prop=time_property(case, variant, args.full_limit if variant == "full" else None),
        cap=0,
        timeout=args.timeout,
        count_method=args.count_method,
        probe_mode=args.probe_mode,
        full_limit=args.full_limit if variant == "full" else None,
        generated_common=generated_common,
    )
    append_row(row)
    print_row_progress(row)
    return [row]


def summarize(rows: list[dict]) -> dict:
    summary: dict[str, dict[str, dict]] = {}
    for row in rows:
        case_summary = summary.setdefault(row["case"], {})
        variant_summary = case_summary.setdefault(
            row["variant"],
            {
                "all_prefixes": 0,
                "specific_prefixes": 0,
                "noCheck_prefixes": 0,
                "closed_prefixes": 0,
                "cumulative_state_estimate": 0,
                "all_lower_bound": 0,
                "specific_lower_bound": 0,
                "noCheck_lower_bound": 0,
                "closed_lower_bound": 0,
                "cumulative_state_lower_bound": 0,
                "total_prefixes": 0,
                "elapsed_ms": 0,
                "maude_rewrites_sum": 0,
                "maude_cpu_ms_sum": 0,
                "maude_real_ms_sum": 0,
                "time_elapsed_ms": 0,
                "time_maude_rewrites_sum": 0,
                "time_maude_cpu_ms_sum": 0,
                "time_maude_real_ms_sum": 0,
                "time_has_solution": None,
                "queries": 0,
                "timeouts": 0,
                "capped_queries": 0,
                "incomplete_queries": 0,
                "exact_counts": True,
                "errors": [],
                "positive_depths": {phase: [] for phase in PHASES},
            },
        )
        if row["phase"] == "time":
            variant_summary["time_elapsed_ms"] += int(row.get("elapsed_ms") or 0)
            variant_summary["time_maude_rewrites_sum"] += int(row.get("maude_rewrites_sum") or 0)
            variant_summary["time_maude_cpu_ms_sum"] += int(row.get("maude_cpu_ms_sum") or 0)
            variant_summary["time_maude_real_ms_sum"] += int(row.get("maude_real_ms_sum") or 0)
            variant_summary["time_has_solution"] = int(row["solution_count"]) > 0
            variant_summary["queries"] += 1
            if row.get("timeout"):
                variant_summary["timeouts"] += 1
            if row.get("error"):
                variant_summary["errors"].append(
                    {
                        "phase": row["phase"],
                        "depths": row["depths"],
                        "error": row["error"],
                        "raw_stdout": row["raw_stdout"],
                    }
                )
            continue

        key = f"{row['phase']}_prefixes"
        lower_key = f"{row['phase']}_lower_bound"
        if row.get("complete"):
            variant_summary[key] += int(row["solution_count"])
            variant_summary["cumulative_state_estimate"] += int(row["solution_count"])
            variant_summary["total_prefixes"] += int(row["solution_count"])
        else:
            variant_summary["incomplete_queries"] += 1
            variant_summary["exact_counts"] = False
        variant_summary[lower_key] += int(row.get("lower_bound", row["solution_count"]))
        variant_summary["cumulative_state_lower_bound"] += int(row.get("lower_bound", row["solution_count"]))
        variant_summary["elapsed_ms"] += int(row.get("elapsed_ms") or 0)
        variant_summary["maude_rewrites_sum"] += int(row.get("maude_rewrites_sum") or 0)
        variant_summary["maude_cpu_ms_sum"] += int(row.get("maude_cpu_ms_sum") or 0)
        variant_summary["maude_real_ms_sum"] += int(row.get("maude_real_ms_sum") or 0)
        variant_summary["queries"] += 1
        if row.get("timeout"):
            variant_summary["timeouts"] += 1
        if row.get("capped"):
            variant_summary["capped_queries"] += 1
        if row.get("error"):
            variant_summary["errors"].append(
                {
                    "phase": row["phase"],
                    "depths": row["depths"],
                    "error": row["error"],
                    "raw_stdout": row["raw_stdout"],
                }
            )
        if int(row["solution_count"]) > 0 and not row.get("timeout"):
            variant_summary["positive_depths"][row["phase"]].append(row["depths"])

    for case_summary in summary.values():
        if "full" in case_summary and "scoped" in case_summary:
            counts_exact = case_summary["full"]["exact_counts"] and case_summary["scoped"]["exact_counts"]
            full = case_summary["full"]["cumulative_state_estimate"]
            scoped = case_summary["scoped"]["cumulative_state_estimate"]
            case_summary["state_estimate_full_over_scoped"] = (
                None if (not counts_exact or scoped == 0) else full / scoped
            )
            case_summary["prefix_reduction_full_over_scoped"] = (
                None if (not counts_exact or scoped == 0) else full / scoped
            )
            full_closed = case_summary["full"]["closed_prefixes"]
            scoped_closed = case_summary["scoped"]["closed_prefixes"]
            case_summary["closed_count_full_over_scoped"] = (
                None if (not counts_exact or scoped_closed == 0) else full_closed / scoped_closed
            )
            full_time = case_summary["full"]["elapsed_ms"]
            scoped_time = case_summary["scoped"]["elapsed_ms"]
            case_summary["elapsed_reduction_full_over_scoped"] = (
                None if scoped_time == 0 else full_time / scoped_time
            )
            full_star_time = case_summary["full"]["time_elapsed_ms"]
            scoped_star_time = case_summary["scoped"]["time_elapsed_ms"]
            case_summary["star_time_full_over_scoped"] = (
                None if scoped_star_time == 0 else full_star_time / scoped_star_time
            )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--maude",
        "--maude-bin",
        dest="maude",
        type=Path,
        default=DEFAULT_MAUDE,
        help="Path to the Maude executable. Defaults to MAUDE_BIN or the repo-local maude/maude/maude-3.5.1/maude.",
    )
    parser.add_argument("--case", choices=["all", *CASES.keys()], default="all")
    parser.add_argument("--variant", choices=["all", "scoped", "full"], default="all")
    parser.add_argument("--max-pre", type=int, default=6)
    parser.add_argument("--max-mid", type=int, default=6)
    parser.add_argument("--max-post", type=int, default=6)
    parser.add_argument("--solution-cap", type=int, default=20)
    parser.add_argument(
        "--full-limit",
        type=int,
        default=None,
        help=(
            "For full variants, build full-K as the CVE-specific BehaviorDVSpec plus "
            "K-1 irrelevant RFC BehaviorDVSpec entries. Summary keys become full-K."
        ),
    )
    parser.add_argument(
        "--full-sample-method",
        choices=["prefix", "random"],
        default="prefix",
        help=(
            "How to choose the K-1 irrelevant RFC BehaviorDVSpec entries for full variants. "
            "prefix preserves the old first-K behavior; random uses --full-seed."
        ),
    )
    parser.add_argument(
        "--full-seed",
        type=int,
        default=None,
        help="Random seed used when --full-sample-method random is selected.",
    )
    parser.add_argument(
        "--full-sources",
        default=" ".join(DEFAULT_FULL_SOURCES),
        help=(
            "Space-separated RFC source keys used as the full-k irrelevant pool. "
            "Available keys: " + ", ".join(SOURCE_FILES)
        ),
    )
    parser.add_argument(
        "--count-method",
        choices=["linear", "binary"],
        default="linear",
        help="How to count nth strategy solutions. binary first probes 1,2,4,... up to the cap, then binary-searches the first false index.",
    )
    parser.add_argument(
        "--probe-mode",
        choices=["single", "batch"],
        default="single",
        help=(
            "single runs one Maude process per solution-index probe. "
            "batch groups binary exponential probes into one Maude driver with multiple reductions."
        ),
    )
    parser.add_argument("--zero-streak", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--mode", choices=["scan", "fixed", "time", "summarize"], default="scan")
    parser.add_argument("--fixed-depths-file", type=Path, default=SUMMARY_JSON)
    parser.add_argument("--fixed-depths-variant", choices=["scoped", "full"], default="scoped")
    parser.add_argument(
        "--summary-scope",
        choices=["current-run", "all-results"],
        default="current-run",
        help="Use current-run for the printed/written summary of this invocation; use all-results to summarize accumulated results.jsonl.",
    )
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args()


def main() -> int:
    global CURRENT_FULL_SAMPLE_METHOD, CURRENT_FULL_SEED, CURRENT_FULL_SOURCES
    args = parse_args()

    if args.mode == "summarize":
        summary = summarize(load_result_rows())
        SUMMARY_JSON.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    maude = args.maude.resolve()
    if not maude.exists():
        print(f"Maude binary not found: {maude}", file=sys.stderr)
        return 2
    if args.solution_cap < 0:
        print("--solution-cap must be non-negative", file=sys.stderr)
        return 2
    if args.full_limit is not None and args.full_limit <= 0:
        print("--full-limit must be positive", file=sys.stderr)
        return 2
    if args.variant == "scoped" and args.full_limit is not None:
        print("--full-limit only applies to full variants", file=sys.stderr)
        return 2
    if args.full_sample_method == "random" and args.full_seed is None:
        print("--full-seed is required with --full-sample-method random", file=sys.stderr)
        return 2
    if args.full_sample_method == "prefix" and args.full_seed is not None:
        print("--full-seed only applies with --full-sample-method random", file=sys.stderr)
        return 2
    full_sources = tuple(args.full_sources.split())
    if not full_sources:
        print("--full-sources must contain at least one source", file=sys.stderr)
        return 2
    unknown_sources = [source for source in full_sources if source not in SOURCE_FILES]
    if unknown_sources:
        print(f"unknown --full-sources entries: {' '.join(unknown_sources)}", file=sys.stderr)
        return 2

    CURRENT_FULL_SAMPLE_METHOD = args.full_sample_method
    CURRENT_FULL_SEED = args.full_seed
    CURRENT_FULL_SOURCES = full_sources

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    GEN_DIR.mkdir(parents=True, exist_ok=True)

    if args.reset:
        for path in [RESULTS_JSONL, SUMMARY_JSON]:
            if path.exists():
                path.unlink()

    selected_cases = list(CASES.values()) if args.case == "all" else [CASES[args.case]]
    selected_variants = ["scoped", "full"] if args.variant == "all" else [args.variant]
    generated_common = (
        generate_common(selected_cases, args.full_limit)
        if "full" in selected_variants
        else None
    )

    all_rows: list[dict] = []
    fixed_summary: dict | None = None
    if args.mode == "fixed":
        if not args.fixed_depths_file.exists():
            print(f"fixed depths file not found: {args.fixed_depths_file}", file=sys.stderr)
            return 2
        fixed_summary = json.loads(args.fixed_depths_file.read_text())

    for case in selected_cases:
        for variant in selected_variants:
            print(
                f"[rq4] case={case.case} variant={result_variant_name(variant, args.full_limit if variant == 'full' else None)}",
                flush=True,
            )
            if args.mode == "fixed":
                assert fixed_summary is not None
                depths_by_phase = (
                    fixed_summary
                    .get(case.case, {})
                    .get(args.fixed_depths_variant, {})
                    .get("positive_depths", {})
                )
                rows = run_case_variant_fixed(args, case, variant, maude, depths_by_phase, generated_common)
            elif args.mode == "time":
                rows = run_case_variant_time(args, case, variant, maude, generated_common)
            else:
                rows = run_case_variant(args, case, variant, maude, generated_common)
            all_rows.extend(rows)

    summary_rows = all_rows if args.summary_scope == "current-run" else load_result_rows()
    summary = summarize(summary_rows)
    SUMMARY_JSON.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
