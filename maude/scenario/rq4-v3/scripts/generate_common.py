#!/usr/bin/env python3
"""Generate RQ4-v3 full-catalog BehaviorDVSpec sets.

The generated common.maude intentionally materializes the RFC catalog and the
synthetic cipher-suite catalog so the experiment input is inspectable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


RQ4_V3_DIR = Path(__file__).resolve().parents[1]
SCENARIO_DIR = RQ4_V3_DIR.parent
REPO = SCENARIO_DIR.parent.parent
MAUDE_DIR = REPO / "maude"
RFC_DIR = SCENARIO_DIR / "rfc"
OUT_FILE = RQ4_V3_DIR / "common.maude"

TARGET_IRRELEVANT_SIZES = (
    *range(4999, 50000, 5000),
    59999,
    69999,
    79999,
    89999,
    99999,
)
RFC_AGGREGATE_OP = "rq4v3RfcBehaviorDVSpecSet"
SYNTHETIC_PREFIX = "rq4v3SyntheticCipherBlock"
COMMON_BEHAVIOR_ID = "'rq4v3-full-bdv"

SYNTHETIC_ACTION_PROPOSITIONS = (
    "ruleLabel('buildClientHelloV2)",
    "ruleLabel('buildServerHelloV2)",
    "ruleLabel('buildClientHelloV3)",
    "ruleLabel('buildServerHelloV3) and appliedNode(server)",
    "ruleLabel('buildClientHelloV3) and appliedNode(client) and "
    "featureMap(@reconnectInProgress |-> av[true])",
    "ruleLabel('buildHelloRetryRequestV3) and appliedNode(server)",
)


@dataclass(frozen=True)
class Source:
    name: str
    path: Path


@dataclass(frozen=True)
class SpecBlock:
    source: str
    index: int
    body: str
    tuple_count: int


SOURCES = (
    Source("5246-core", RFC_DIR / "5246-core.maude"),
    Source("8446-core", RFC_DIR / "8446-core.maude"),
    Source("hrr", RFC_DIR / "hrr.maude"),
    Source("psk", RFC_DIR / "psk.maude"),
)

EQ_RE = re.compile(r"^\s*eq\s+behaviorDeviationSpecification(\d+)\s*=")
LABEL_RE = re.compile(r"\{'[^,\s]+")
CIPHER_SUITE_RE = re.compile(r"\s*op\s+([A-Za-z0-9-]+)\s*:\s*->\s*CipherSuite\s*\[ctor\]\s*\.")


def strip_equation_dot(line: str) -> str:
    return re.sub(r"\s*\.\s*$", "", line.rstrip())


def relabel_body(body: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return "{" + COMMON_BEHAVIOR_ID

    return LABEL_RE.sub(replace, body)


def extract_spec_blocks(source: Source) -> list[SpecBlock]:
    lines = source.path.read_text(encoding="utf-8").splitlines()
    blocks: list[SpecBlock] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        match = EQ_RE.match(line)
        if not match:
            i += 1
            continue

        index = int(match.group(1))
        eq_lines: list[str] = []
        rest = line.split("=", 1)[1].strip()
        if rest:
            eq_lines.append(rest)

        while not line.strip().endswith("."):
            i += 1
            if i >= len(lines):
                raise ValueError(f"unterminated behaviorDeviationSpecification{index} in {source.path}")
            line = lines[i]
            eq_lines.append(line.rstrip())

        if eq_lines:
            eq_lines[-1] = strip_equation_dot(eq_lines[-1])

        body = "\n".join(eq_lines).strip()
        if body == "empty":
            i += 1
            continue

        body = relabel_body(body)
        tuple_count = len(LABEL_RE.findall(body))
        blocks.append(SpecBlock(source.name, index, body, tuple_count))
        i += 1

    return blocks


def indent_body(body: str) -> str:
    return "\n".join(("     " + line.lstrip()) if line.strip() else "" for line in body.splitlines())


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


def compact_term(term: str) -> str:
    return re.sub(r"\s+", " ", term).strip()


def read_cipher_suites() -> list[str]:
    suites: list[str] = []
    seen: set[str] = set()
    for line in (MAUDE_DIR / "ciphersuite.maude").read_text(encoding="utf-8").splitlines():
        match = CIPHER_SUITE_RE.match(line)
        if not match:
            continue
        suite = match.group(1)
        if suite not in seen:
            suites.append(suite)
            seen.add(suite)
    if len(suites) < 3:
        raise RuntimeError("expected at least three CipherSuite constructors")
    return suites


def synthetic_entries(count: int) -> list[str]:
    suites = read_cipher_suites()
    entries: list[str] = []
    entry_id = 1
    for first in suites:
        for second in suites:
            for third in suites:
                ap = SYNTHETIC_ACTION_PROPOSITIONS[(entry_id - 1) % len(SYNTHETIC_ACTION_PROPOSITIONS)]
                entries.append(
                    f"{{{COMMON_BEHAVIOR_ID}, {ap}, "
                    f"setM(#cipherSuites, mv[{first} {second} {third}])}}"
                )
                entry_id += 1
                if len(entries) == count:
                    return entries
    raise ValueError(f"only generated {len(entries)} synthetic entries; requested {count}")


def render_rfc_set() -> tuple[str, int, int, int]:
    blocks: list[SpecBlock] = []
    for source in SOURCES:
        blocks.extend(extract_spec_blocks(source))

    tuple_count = sum(block.tuple_count for block in blocks)
    unique_entries = {
        compact_term(entry)
        for block in blocks
        for entry in split_set_entries(block.body)
    }
    unique_count = len(unique_entries)
    out: list[str] = [
        f"  --- RFC sources: {' '.join(source.name for source in SOURCES)}",
        f"  --- unified BehaviorId: {COMMON_BEHAVIOR_ID}",
        f"  --- non-empty behaviorDeviationSpecification blocks: {len(blocks)}",
        f"  --- BehaviorDVSpec entries before Set duplicate elimination: {tuple_count}",
        f"  --- BehaviorDVSpec entries after Set duplicate elimination: {unique_count}",
        f"  op {RFC_AGGREGATE_OP} : -> Set{{BehaviorDVSpec}} .",
        f"  eq {RFC_AGGREGATE_OP} =",
    ]
    for pos, block in enumerate(blocks):
        out.append(f"     --- {block.source}: behaviorDeviationSpecification{block.index}")
        body = indent_body(block.body)
        body += "," if pos + 1 < len(blocks) else " ."
        out.append(body)
    return "\n".join(out), len(blocks), tuple_count, unique_count


def render_synthetic_blocks(rfc_unique_count: int) -> tuple[list[str], list[str]]:
    needed_totals = [target - rfc_unique_count for target in TARGET_IRRELEVANT_SIZES]
    if any(total < 0 for total in needed_totals):
        raise ValueError("RFC catalog is already larger than the first target")

    total_synthetic = needed_totals[-1]
    entries = synthetic_entries(total_synthetic)
    rendered_blocks: list[str] = []
    block_names: list[str] = []
    start = 0
    previous_total = 0
    for index, needed_total in enumerate(needed_totals, start=1):
        size = needed_total - previous_total
        block_entries = entries[start : start + size]
        block_name = f"{SYNTHETIC_PREFIX}{index}"
        block_names.append(block_name)

        out = [
            f"  --- synthetic cipher-suite triple entries {start + 1}..{start + size}",
            f"  op {block_name} : -> Set{{BehaviorDVSpec}} .",
            f"  eq {block_name} =",
        ]
        for pos, entry in enumerate(block_entries):
            suffix = "," if pos + 1 < len(block_entries) else " ."
            out.append(f"     {entry}{suffix}")
        rendered_blocks.append("\n".join(out))

        start += size
        previous_total = needed_total
    return rendered_blocks, block_names


def render_bdv_sets(block_names: list[str]) -> str:
    out: list[str] = []
    accumulated_terms = [RFC_AGGREGATE_OP]
    for target, block_name in zip(TARGET_IRRELEVANT_SIZES, block_names):
        accumulated_terms.append(block_name)
        op_name = f"bdvSet{target}"
        out.extend(
            [
                f"  --- Add one CVE-triggering BehaviorDVSpec to {op_name} to obtain total catalog size {target + 1}.",
                f"  op {op_name} : -> Set{{BehaviorDVSpec}} .",
                f"  eq {op_name} = {', '.join(accumulated_terms)} .",
                "",
            ]
        )
    return "\n".join(out).rstrip()


def main() -> None:
    rfc_text, block_count, rfc_count, rfc_unique_count = render_rfc_set()
    synthetic_texts, block_names = render_synthetic_blocks(rfc_unique_count)

    rendered: list[str] = [
        "--- Generated by scripts/generate_common.py; do not edit by hand.",
        "--- bdvSet4999, bdvSet9999, ..., bdvSet99999 exclude the CVE trigger.",
        "--- Add one CVE-triggering BehaviorDVSpec to obtain 5000, 10000, ..., 100000 total specs.",
        "load ../../requirements/mixed-base.maude",
        "load ../threat-module.maude",
        "",
        "smod RQ4-V3-PRE-DEFINED-BEHAVIOR-DEVIATION-SPECIFICATION is",
        "  protecting RUN-SCENARIO .",
        "  protecting SET{BehaviorDVSpec} .",
        "",
        rfc_text,
        "",
        *synthetic_texts,
        "",
        render_bdv_sets(block_names),
        "endsm",
        "",
    ]

    OUT_FILE.write_text("\n\n".join(rendered), encoding="utf-8")
    print(f"RFC blocks: {block_count}")
    print(f"RFC BehaviorDVSpec entries before Set duplicate elimination: {rfc_count}")
    print(f"RFC BehaviorDVSpec entries after Set duplicate elimination: {rfc_unique_count}")
    print(f"synthetic BehaviorDVSpec entries: {TARGET_IRRELEVANT_SIZES[-1] - rfc_unique_count}")
    for target in TARGET_IRRELEVANT_SIZES:
        print(f"bdvSet{target}: target Set cardinality {target}")
    print(f"wrote {OUT_FILE.relative_to(REPO)}")


if __name__ == "__main__":
    main()
