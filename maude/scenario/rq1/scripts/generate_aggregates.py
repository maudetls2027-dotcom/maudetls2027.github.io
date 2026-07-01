#!/usr/bin/env python3
"""Generate RQ1 pattern-specific RFC aggregate modules and a job manifest."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


RQ1_DIR = Path(__file__).resolve().parents[1]
MANIFEST = RQ1_DIR / "manifest.json"
PATTERNS = ("P1", "P2", "P3", "P4", "P5")


def rng(start: int, end: int) -> list[int]:
    return list(range(start, end + 1))


def pascal(value: str) -> str:
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))


@dataclass(frozen=True)
class ConfSpec:
    op: str
    expr: str


@dataclass(frozen=True)
class ChunkSpec:
    chunk_id: str
    conf_op: str
    patterns: dict[str, list[int]]
    expected: dict[str, int]


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    display: str
    protocol: str
    protocol_version: str
    module_file: str
    module_name: str
    load_path: str
    source_module: str
    confs: list[ConfSpec]
    chunks: list[ChunkSpec]


SOURCES: list[SourceSpec] = [
    SourceSpec(
        source_id="tls12-core",
        display="TLS 1.2 RFC 5246 core",
        protocol="tls12",
        protocol_version="TLS-12",
        module_file="tls12-core.maude",
        module_name="RQ1-TLS12-CORE",
        load_path="../rfc/5246-core.maude",
        source_module="RFC-5246-CORE",
        confs=[ConfSpec("rq1Tls12CoreConf", "initConf1 tester(N2 . SI) target(N1 . CI)")],
        chunks=[
            ChunkSpec(
                "tls12-core",
                "rq1Tls12CoreConf",
                {
                    "P1": [7] + rng(9, 12) + rng(25, 31),
                    "P2": rng(44, 45),
                    "P3": rng(1, 5)
                    + rng(13, 14)
                    + rng(16, 24)
                    + rng(32, 34)
                    + rng(36, 39)
                    + [42, 46, 49, 51],
                    "P4": [15, 35],
                    "P5": [47],
                },
                {"P1": 73, "P2": 2, "P3": 310, "P4": 2, "P5": 1},
            )
        ],
    ),
    SourceSpec(
        source_id="tls12-additional",
        display="TLS 1.2 RFC 5246 additional",
        protocol="tls12",
        protocol_version="TLS-12",
        module_file="tls12-additional.maude",
        module_name="RQ1-TLS12-ADDITIONAL",
        load_path="../rfc-additional/5246-core.maude",
        source_module="RFC-5246-CORE-ADDITIONAL",
        confs=[ConfSpec("rq1Tls12AdditionalConf", "initConf1 tester(N2 . SI) target(N1 . CI)")],
        chunks=[
            ChunkSpec(
                "tls12-additional",
                "rq1Tls12AdditionalConf",
                {
                    "P1": [9],
                    "P2": [],
                    "P3": rng(10, 13),
                    "P4": rng(7, 8),
                    "P5": rng(1, 6),
                },
                {"P1": 256, "P2": 0, "P3": 300, "P4": 2, "P5": 6},
            )
        ],
    ),
    SourceSpec(
        source_id="tls13-core",
        display="TLS 1.3 RFC 8446 core",
        protocol="tls13",
        protocol_version="TLS-13",
        module_file="tls13-core.maude",
        module_name="RQ1-TLS13-CORE",
        load_path="../rfc/8446-core.maude",
        source_module="RFC-8446-CORE",
        confs=[ConfSpec("rq1Tls13CoreConf", "initConf tester(N2 . SI) target(N1 . CI)")],
        chunks=[
            ChunkSpec(
                "tls13-core",
                "rq1Tls13CoreConf",
                {
                    "P1": rng(8, 10) + rng(40, 46) + rng(51, 55) + rng(58, 64),
                    "P2": rng(5, 7) + rng(47, 48) + [57],
                    "P3": [1] + rng(3, 4) + rng(12, 39) + rng(49, 50) + rng(65, 93),
                    "P4": [11, 56],
                    "P5": [],
                },
                {"P1": 162, "P2": 6, "P3": 556, "P4": 2, "P5": 0},
            )
        ],
    ),
    SourceSpec(
        source_id="tls13-hrr",
        display="TLS 1.3 HRR",
        protocol="tls13",
        protocol_version="TLS-13",
        module_file="tls13-hrr.maude",
        module_name="RQ1-TLS13-HRR",
        load_path="../rfc/hrr.maude",
        source_module="RFC-HRR",
        confs=[ConfSpec("rq1Tls13HrrConf", "initConf tester(N2 . SI) target(N1 . CI)")],
        chunks=[
            ChunkSpec(
                "tls13-hrr",
                "rq1Tls13HrrConf",
                {
                    "P1": rng(1, 6) + rng(9, 10) + rng(32, 35) + rng(44, 49) + rng(52, 53),
                    "P2": rng(7, 8) + rng(28, 31) + rng(50, 51),
                    "P3": rng(11, 22) + rng(24, 27) + rng(36, 43) + rng(54, 64),
                    "P4": [],
                    "P5": [],
                },
                {"P1": 157, "P2": 8, "P3": 339, "P4": 0, "P5": 0},
            )
        ],
    ),
    SourceSpec(
        source_id="tls13-psk",
        display="TLS 1.3 PSK",
        protocol="tls13",
        protocol_version="TLS-13",
        module_file="tls13-psk.maude",
        module_name="RQ1-TLS13-PSK",
        load_path="../rfc/psk.maude",
        source_module="RFC-PSK",
        confs=[
            ConfSpec("rq1Tls13PskDheConf", "initConf-psk-dhe tester(N2 . SI) target(N1 . CI)"),
            ConfSpec("rq1Tls13PskDheHrrConf", "initConf-psk-dhe-hrr tester(N2 . SI) target(N1 . CI)"),
            ConfSpec("rq1Tls13PskKeConf", "initConf-psk-ke tester(N2 . SI) target(N1 . CI)"),
        ],
        chunks=[
            ChunkSpec(
                "tls13-psk-dhe",
                "rq1Tls13PskDheConf",
                {
                    "P1": rng(5, 8),
                    "P2": rng(1, 4),
                    "P3": rng(9, 13),
                    "P4": [],
                    "P5": [],
                },
                {"P1": 34, "P2": 4, "P3": 108, "P4": 0, "P5": 0},
            ),
            ChunkSpec(
                "tls13-psk-dhe-hrr",
                "rq1Tls13PskDheHrrConf",
                {
                    "P1": rng(17, 18) + rng(23, 29) + rng(34, 37) + rng(46, 47) + rng(52, 61),
                    "P2": rng(15, 16) + rng(30, 33) + rng(44, 45),
                    "P3": rng(19, 22) + rng(38, 42) + rng(48, 51) + rng(62, 95),
                    "P4": [],
                    "P5": [],
                },
                {"P1": 166, "P2": 8, "P3": 487, "P4": 0, "P5": 0},
            ),
            ChunkSpec(
                "tls13-psk-ke",
                "rq1Tls13PskKeConf",
                {
                    "P1": rng(101, 103) + rng(106, 114) + rng(117, 120),
                    "P2": rng(99, 100) + rng(104, 105),
                    "P3": rng(96, 97) + rng(115, 116) + rng(121, 141),
                    "P4": [],
                    "P5": [],
                },
                {"P1": 79, "P2": 4, "P3": 302, "P4": 0, "P5": 0},
            ),
        ],
    ),
    SourceSpec(
        source_id="tls13-additional-core",
        display="TLS 1.3 RFC 8446 core additional",
        protocol="tls13",
        protocol_version="TLS-13",
        module_file="tls13-additional-core.maude",
        module_name="RQ1-TLS13-ADDITIONAL-CORE",
        load_path="../rfc-additional/8446-core.maude",
        source_module="RFC-8446-CORE-ADDITIONAL",
        confs=[ConfSpec("rq1Tls13AdditionalCoreConf", "initConf tester(N2 . SI) target(N1 . CI)")],
        chunks=[
            ChunkSpec(
                "tls13-additional-core",
                "rq1Tls13AdditionalCoreConf",
                {"P1": [], "P2": [], "P3": [], "P4": [4], "P5": rng(1, 3)},
                {"P1": 0, "P2": 0, "P3": 0, "P4": 1, "P5": 3},
            )
        ],
    ),
    SourceSpec(
        source_id="tls13-additional-hrr",
        display="TLS 1.3 HRR additional",
        protocol="tls13",
        protocol_version="TLS-13",
        module_file="tls13-additional-hrr.maude",
        module_name="RQ1-TLS13-ADDITIONAL-HRR",
        load_path="../rfc-additional/hrr.maude",
        source_module="RFC-HRR-ADDITIONAL",
        confs=[
            ConfSpec("rq1Tls13AdditionalHrrConf", "initConf tester(N2 . SI) target(N1 . CI)"),
            ConfSpec("rq1Tls13AdditionalHrrClientAuthConf", "initConfClientAuth tester(N2 . SI) target(N1 . CI)"),
        ],
        chunks=[
            ChunkSpec(
                "tls13-additional-hrr",
                "rq1Tls13AdditionalHrrConf",
                {"P1": [], "P2": [], "P3": [], "P4": rng(3, 5), "P5": [1]},
                {"P1": 0, "P2": 0, "P3": 0, "P4": 3, "P5": 1},
            ),
            ChunkSpec(
                "tls13-additional-hrr-client-auth",
                "rq1Tls13AdditionalHrrClientAuthConf",
                {"P1": [], "P2": [], "P3": [], "P4": [], "P5": [2]},
                {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 1},
            ),
        ],
    ),
    SourceSpec(
        source_id="tls13-additional-psk",
        display="TLS 1.3 PSK additional",
        protocol="tls13",
        protocol_version="TLS-13",
        module_file="tls13-additional-psk.maude",
        module_name="RQ1-TLS13-ADDITIONAL-PSK",
        load_path="../rfc-additional/psk.maude",
        source_module="RFC-8446-ADDITIONAL",
        confs=[
            ConfSpec("rq1Tls13AdditionalPskDheConf", "initConf-psk-dhe tester(N2 . SI) target(N1 . CI)"),
            ConfSpec("rq1Tls13AdditionalPskDheHrrConf", "initConf-psk-dhe-hrr tester(N2 . SI) target(N1 . CI)"),
            ConfSpec("rq1Tls13AdditionalPskKeConf", "initConf-psk-ke tester(N2 . SI) target(N1 . CI)"),
        ],
        chunks=[
            ChunkSpec(
                "tls13-additional-psk-dhe",
                "rq1Tls13AdditionalPskDheConf",
                {"P1": [], "P2": [], "P3": [], "P4": [4, 6], "P5": [1]},
                {"P1": 0, "P2": 0, "P3": 0, "P4": 2, "P5": 1},
            ),
            ChunkSpec(
                "tls13-additional-psk-dhe-hrr",
                "rq1Tls13AdditionalPskDheHrrConf",
                {"P1": [], "P2": [], "P3": [], "P4": rng(7, 10), "P5": [3]},
                {"P1": 0, "P2": 0, "P3": 0, "P4": 4, "P5": 1},
            ),
            ChunkSpec(
                "tls13-additional-psk-ke",
                "rq1Tls13AdditionalPskKeConf",
                {"P1": [], "P2": [], "P3": [], "P4": [5], "P5": [2]},
                {"P1": 0, "P2": 0, "P3": 0, "P4": 1, "P5": 1},
            ),
        ],
    ),
]


def op_base(chunk_id: str, pattern: str) -> str:
    return f"rq1{pascal(chunk_id)}{pattern}"


def label_for(chunk_id: str, pattern: str, scen: int) -> str:
    return f"'rq1-{chunk_id}-{pattern.lower()}-scen{scen}"


def render_label_expr(labels: list[str]) -> str:
    if not labels:
        return "anyStep"
    return " or\n     ".join(f"ruleLabel({label})" for label in labels)


def render_set_expr(chunk: ChunkSpec, pattern: str) -> str:
    scens = chunk.patterns.get(pattern, [])
    if not scens:
        return "empty"
    parts = [
        f"rq1Relabel({label_for(chunk.chunk_id, pattern, scen)}, behaviorDeviationSpecification{scen})"
        for scen in scens
    ]
    return " ,\n     ".join(parts)


def render_property_expr(chunk: ChunkSpec, pattern: str) -> str:
    scens = chunk.patterns.get(pattern, [])
    if not scens:
        return "anyStep"
    parts = [
        (
            f"rq1RelabelScenario('scen{scen}, {label_for(chunk.chunk_id, pattern, scen)}, "
            f"scenarioProperty{scen})"
        )
        for scen in scens
    ]
    return " |\n     ".join(parts)


def render_source(source: SourceSpec) -> str:
    lines: list[str] = [
        "--- Generated by scripts/generate_aggregates.py; do not edit by hand.",
        "load common.maude",
        f"load {source.load_path}",
        "",
        f"smod {source.module_name} is",
        f"  protecting {source.source_module} .",
        "  protecting RQ1-COMMON .",
        "",
    ]
    for conf in source.confs:
        lines.extend(
            [
                f"  op {conf.op} : -> TLSConfiguration .",
                f"  eq {conf.op} = {conf.expr} .",
                "",
            ]
        )
    for chunk in source.chunks:
        lines.append(f"  --- {chunk.chunk_id}")
        for pattern in PATTERNS:
            base = op_base(chunk.chunk_id, pattern)
            set_op = f"{base}Set"
            labels_op = f"{base}Labels"
            property_op = f"{base}Property"
            set_expr = render_set_expr(chunk, pattern)
            label_expr = render_label_expr(
                [label_for(chunk.chunk_id, pattern, scen) for scen in chunk.patterns.get(pattern, [])]
            )
            property_expr = render_property_expr(chunk, pattern)
            lines.extend(
                [
                    f"  op {set_op} : -> Set{{BehaviorDVSpec}} .",
                    f"  eq {set_op} =",
                    f"     {set_expr} .",
                    "",
                    f"  op {labels_op} : -> StepProperty .",
                    f"  eq {labels_op} =",
                    f"     {label_expr} .",
                    "",
                    f"  op {property_op} : -> ScenarioProperty .",
                    f"  eq {property_op} =",
                    f"     {property_expr} .",
                    "",
                ]
            )
    lines.extend(["endsm", ""])
    return "\n".join(lines)


def build_manifest() -> list[dict[str, object]]:
    jobs: list[dict[str, object]] = []
    for source in SOURCES:
        for chunk in source.chunks:
            for pattern in PATTERNS:
                expected = chunk.expected[pattern]
                if expected == 0:
                    continue
                base = op_base(chunk.chunk_id, pattern)
                scenario_kind = "terminal" if pattern == "P3" else "error"
                scenario_op = (
                    "rq1TerminalScenarioV2"
                    if source.protocol == "tls12" and scenario_kind == "terminal"
                    else "rq1ErrorScenarioV2"
                    if source.protocol == "tls12"
                    else "rq1TerminalScenarioV3"
                    if scenario_kind == "terminal"
                    else "rq1ErrorScenarioV3"
                )
                jobs.append(
                    {
                        "job_id": f"{chunk.chunk_id}-{pattern.lower()}",
                        "source_id": source.source_id,
                        "source_display": source.display,
                        "chunk_id": chunk.chunk_id,
                        "protocol": source.protocol,
                        "protocol_version": source.protocol_version,
                        "pattern": pattern,
                        "module_file": source.module_file,
                        "module_name": source.module_name,
                        "conf_op": chunk.conf_op,
                        "bds_op": f"{base}Set",
                        "labels_op": f"{base}Labels",
                        "property_op": f"{base}Property",
                        "scenario_kind": scenario_kind,
                        "scenario_op": scenario_op,
                        "expected_instances": expected,
                        "scens": chunk.patterns[pattern],
                    }
                )
    return jobs


def main() -> None:
    for source in SOURCES:
        (RQ1_DIR / source.module_file).write_text(render_source(source), encoding="utf-8")
        print(f"wrote {source.module_file}")
    jobs = build_manifest()
    MANIFEST.write_text(json.dumps({"jobs": jobs}, indent=2) + "\n", encoding="utf-8")
    total = sum(int(job["expected_instances"]) for job in jobs)
    print(f"wrote manifest.json ({len(jobs)} jobs, {total} expected instances)")


if __name__ == "__main__":
    main()
