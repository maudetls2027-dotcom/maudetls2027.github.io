#!/usr/bin/env python3
"""Measure time for proving that solution index 0 does not exist.

This is intentionally separate from run_strategy_guided_counts.py so the
main RQ4 results.jsonl is not mixed with negative-control timing rows.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve()
RQ4_DIR = SCRIPT.parents[1]
RUNNER_PATH = SCRIPT.with_name("run_strategy_guided_counts.py")

spec = importlib.util.spec_from_file_location("rq4_runner", RUNNER_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"failed to load {RUNNER_PATH}")
rq4 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rq4
spec.loader.exec_module(rq4)

RESULTS_JSONL = rq4.STATE_DIR / "no_solution_time_results.jsonl"
CIPHER_SUITE_RE = re.compile(r"\s*op\s+([A-Za-z0-9-]+)\s*:\s*->\s*CipherSuite\s*\[ctor\]\s*\.")

SYNTHETIC_CIPHER_APS = (
    "ruleLabel('buildClientHelloV2)",
    "ruleLabel('buildServerHelloV2)",
    "ruleLabel('buildClientHelloV3)",
    "ruleLabel('buildServerHelloV3) and appliedNode(server)",
    "ruleLabel('buildClientHelloV3) and appliedNode(client) and "
    "featureMap(@reconnectInProgress |-> av[true])",
    "ruleLabel('buildHelloRetryRequestV3) and appliedNode(server)",
)


def impossible_action_property(case: rq4.Case, variant: str, full_limit: int | None) -> str:
    return rq4.seq_property(
        [
            "(anyStep *)",
            rq4.first_ap(case, variant, full_limit),
            "(anyStep *)",
            case.bypass,
            "(anyStep *)",
            "ruleLabel('rq4-impossible-no-solution)",
        ]
    )


def append_row(row: dict) -> None:
    RESULTS_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_JSONL.open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def read_cipher_suites() -> list[str]:
    suites: list[str] = []
    seen: set[str] = set()
    for line in (rq4.REPO / "maude" / "ciphersuite.maude").read_text().splitlines():
        match = CIPHER_SUITE_RE.match(line)
        if not match:
            continue
        suite = match.group(1)
        if suite not in seen:
            suites.append(suite)
            seen.add(suite)
    if len(suites) < 2:
        raise RuntimeError("expected at least two CipherSuite constructors")
    return suites


def synthetic_cipher_entries(count: int) -> list[tuple[str, str]]:
    if count < 0:
        raise ValueError("synthetic cipher entry count must be non-negative")
    suites = read_cipher_suites()
    entries: list[tuple[str, str]] = []
    next_id = 1
    for left in suites:
        for right in suites:
            if left == right:
                continue
            for ap in SYNTHETIC_CIPHER_APS:
                label = f"rq4-synth-cipher-{next_id:05d}"
                entry = (
                    f"{{'{label}, {ap}, "
                    f"setM(#cipherSuites, mv[{left} {right}])}}"
                )
                entries.append((entry, label))
                next_id += 1
                if len(entries) == count:
                    return entries
    raise ValueError(
        f"could only generate {len(entries)} synthetic cipher entries; requested {count}"
    )


def selected_irrelevant_entries(
    full_sources: tuple[str, ...],
    full_limit: int | None,
    synthetic_count: int,
) -> tuple[list[tuple[str, str]], int, int]:
    entries: list[tuple[str, str]] = []
    for source in full_sources:
        entries.extend(rq4.extract_behavior_entries(rq4.SOURCE_FILES[source], f"rq4-{source}"))

    base_count = len(entries)
    entries.extend(synthetic_cipher_entries(synthetic_count))
    selected = rq4.select_irrelevant_entries(entries, full_limit)
    return selected, base_count, synthetic_count


def synthetic_file_key(
    cases: list[rq4.Case],
    full_limit: int | None,
    synthetic_count: int,
) -> str:
    case_key = "all" if len(cases) > 1 else cases[0].case
    limit_key = rq4.full_file_key(full_limit)
    if synthetic_count > 0:
        limit_key += f"-synthcipher-{synthetic_count}"
    return f"rq4-common-generated.{case_key}.{limit_key}.maude"


def generate_common_with_synthetic(
    cases: list[rq4.Case],
    full_limit: int | None,
    synthetic_count: int,
) -> tuple[Path, dict[str, dict[str, int]]]:
    rq4.GEN_DIR.mkdir(parents=True, exist_ok=True)
    chunks: list[str] = [
        "load ../../common.maude",
        "",
        "smod RQ4-COMMON-GENERATED is",
        "  protecting RQ4-COMMON .",
        "",
    ]
    meta: dict[str, dict[str, int]] = {}

    for case in cases:
        entries, base_count, synth_count = selected_irrelevant_entries(
            rq4.CURRENT_FULL_SOURCES,
            full_limit,
            synthetic_count,
        )
        public_label = rq4.full_behavior_label(case, full_limit)
        full_entries = [rq4.relabel_behavior_entry(case.specific_entry, public_label)]
        full_entries.extend(rq4.relabel_behavior_entry(entry, public_label) for entry, _ in entries)
        meta[case.case] = {
            "base_irrelevant_count": base_count,
            "synthetic_cipher_count": synth_count,
            "selected_irrelevant_count": len(entries),
            "selected_full_total_count": len(full_entries),
        }
        variant = rq4.result_variant_name("full", full_limit)
        print(
            "[rq4-negative] "
            f"full-sample case={case.case} variant={variant} "
            f"sources={' '.join(rq4.CURRENT_FULL_SOURCES)} "
            f"base_irrelevant={base_count} synthetic_cipher={synth_count} "
            f"selected_irrelevant={len(entries)} full_total={len(full_entries)}",
            flush=True,
        )

        chunks.append(
            f"  --- full sample method: {rq4.CURRENT_FULL_SAMPLE_METHOD}; "
            f"seed: {rq4.CURRENT_FULL_SEED}; sources: {' '.join(rq4.CURRENT_FULL_SOURCES)}; "
            f"base irrelevant entries: {base_count}; "
            f"synthetic cipher entries: {synth_count}; "
            f"selected irrelevant entries: {len(entries)}"
        )
        chunks.append(f"  op {rq4.common_bss_name(case, full_limit)} : -> Set{{BehaviorDVSpec}} .")
        chunks.append(f"  eq {rq4.common_bss_name(case, full_limit)} =")
        chunks.append("     " + rq4.make_set_expr(entry for entry, _ in entries) + " .")
        chunks.append("")
        chunks.append(f"  op {rq4.full_bss_name(case, full_limit)} : -> Set{{BehaviorDVSpec}} .")
        chunks.append(f"  eq {rq4.full_bss_name(case, full_limit)} =")
        chunks.append("     " + rq4.make_set_expr(full_entries) + " .")
        chunks.append("")
        chunks.append(f"  op {rq4.all_behavior_ap_name(case, full_limit)} : -> ActionProposition .")
        chunks.append(f"  eq {rq4.all_behavior_ap_name(case, full_limit)} =")
        chunks.append(f"     ruleLabel('{public_label}) .")
        chunks.append("")

    chunks.append("endsm")
    path = rq4.GEN_DIR / synthetic_file_key(cases, full_limit, synthetic_count)
    path.write_text("\n".join(chunks) + "\n")
    return path, meta


def install_synthetic_variant_suffix(synthetic_count: int) -> None:
    if synthetic_count <= 0:
        return
    original = rq4.result_variant_name

    def result_variant_name(variant: str, full_limit: int | None) -> str:
        name = original(variant, full_limit)
        if variant == "full":
            name += f"-synthcipher-{synthetic_count}"
        return name

    rq4.result_variant_name = result_variant_name


def main() -> int:
    parser = argparse.ArgumentParser(
        description="RQ4 negative-control timing: prove rq4HasSolution(..., 0) is false."
    )
    parser.add_argument("--case", choices=["all", *sorted(rq4.CASES)], default="all")
    parser.add_argument("--variant", choices=["full", "scoped"], default="full")
    parser.add_argument(
        "--maude-bin",
        type=Path,
        default=Path(os.environ.get("MAUDE_BIN", str(rq4.DEFAULT_MAUDE))),
    )
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--full-limit", type=int)
    parser.add_argument(
        "--full-sources",
        default="5246-core 8446-core hrr psk",
        help="Space-separated source names used for full variant.",
    )
    parser.add_argument(
        "--full-sample-method",
        choices=["prefix", "random"],
        default="prefix",
    )
    parser.add_argument("--full-seed", type=int)
    parser.add_argument(
        "--synthetic-cipher-count",
        type=int,
        default=0,
        help="Number of synthetic cipher-suite pair BehaviorDVSpec entries to append.",
    )
    parser.add_argument(
        "--target-full-size",
        type=int,
        help=(
            "Target full set size including the CVE trigger. "
            "The script appends enough synthetic cipher-suite entries and uses this as "
            "--full-limit when --full-limit is omitted."
        ),
    )
    args = parser.parse_args()

    if args.variant == "scoped" and args.full_limit is not None:
        parser.error("--full-limit only applies to --variant full")
    if args.full_sample_method == "random" and args.full_seed is None:
        parser.error("--full-seed is required with --full-sample-method random")
    if args.full_sample_method == "prefix" and args.full_seed is not None:
        parser.error("--full-seed only applies with --full-sample-method random")
    if args.variant == "scoped" and (args.synthetic_cipher_count or args.target_full_size):
        parser.error("synthetic full-set options only apply to --variant full")
    if args.synthetic_cipher_count and args.target_full_size:
        parser.error("use either --synthetic-cipher-count or --target-full-size, not both")
    if args.synthetic_cipher_count < 0:
        parser.error("--synthetic-cipher-count must be non-negative")
    if args.target_full_size is not None and args.target_full_size < 1:
        parser.error("--target-full-size must be at least 1")

    full_sources = tuple(args.full_sources.split())
    unknown_sources = [source for source in full_sources if source not in rq4.SOURCE_FILES]
    if unknown_sources:
        parser.error(f"unknown --full-sources entries: {' '.join(unknown_sources)}")

    rq4.CURRENT_FULL_SAMPLE_METHOD = args.full_sample_method
    rq4.CURRENT_FULL_SEED = args.full_seed
    rq4.CURRENT_FULL_SOURCES = full_sources
    rq4.RAW_DIR.mkdir(parents=True, exist_ok=True)
    rq4.GEN_DIR.mkdir(parents=True, exist_ok=True)

    selected_cases = list(rq4.CASES.values()) if args.case == "all" else [rq4.CASES[args.case]]
    full_limit = args.full_limit if args.variant == "full" else None
    synthetic_count = args.synthetic_cipher_count
    if args.target_full_size is not None:
        base_entries = []
        for source in full_sources:
            base_entries.extend(rq4.extract_behavior_entries(rq4.SOURCE_FILES[source], f"rq4-{source}"))
        base_irrelevant = len(base_entries)
        full_limit = full_limit if full_limit is not None else args.target_full_size
        selected_irrelevant_target = rq4.irrelevant_behavior_limit(full_limit)
        if selected_irrelevant_target is None:
            selected_irrelevant_target = max(args.target_full_size - 1, 0)
        synthetic_count = max(selected_irrelevant_target - base_irrelevant, 0)
    install_synthetic_variant_suffix(synthetic_count)
    generated_common = None
    generated_meta: dict[str, dict[str, int]] = {}
    if args.variant == "full":
        if synthetic_count:
            generated_common, generated_meta = generate_common_with_synthetic(
                selected_cases,
                full_limit,
                synthetic_count,
            )
        else:
            generated_common = rq4.generate_common(selected_cases, full_limit)

    rows: list[dict] = []
    for case in selected_cases:
        case_full_limit = full_limit if args.variant == "full" else None
        prop = impossible_action_property(case, args.variant, case_full_limit)
        print(
            "[rq4-negative] "
            f"case={case.case} variant={rq4.result_variant_name(args.variant, case_full_limit)} "
            "query n=0",
            flush=True,
        )
        row = rq4.run_property(
            maude=args.maude_bin,
            case=case,
            variant=args.variant,
            phase="timeNoSolution",
            depths=(),
            prop=prop,
            cap=0,
            timeout=args.timeout,
            count_method="binary",
            probe_mode="single",
            full_limit=case_full_limit,
            generated_common=generated_common,
        )
        if case.case in generated_meta:
            row.update(generated_meta[case.case])
        if args.target_full_size is not None:
            row["target_full_size"] = args.target_full_size
        append_row(row)
        rq4.print_row_progress(row)
        rows.append(row)

    print(json.dumps(rows, indent=2, sort_keys=True))
    print(f"[rq4-negative] wrote {RESULTS_JSONL.relative_to(rq4.RQ4_DIR)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
