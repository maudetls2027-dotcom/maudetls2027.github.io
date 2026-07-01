#!/usr/bin/env python3
"""Generate RQ2 Table IV Maude modules and manifest."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


PATTERNS = ("P1", "P2", "P3", "P4", "P5")
RESULT_TERM_RE = re.compile(r"^result\s+[^:]+:\s*(.*?)(?:\nBye\.|\Z)", re.MULTILINE | re.DOTALL)


CATEGORY_INFO: dict[str, dict[str, str]] = {
    "5246": {"op_part": "Rfc5246", "label": "RFC 5246 core"},
    "8446": {"op_part": "Rfc8446", "label": "RFC 8446 core"},
    "hrr": {"op_part": "HrrBucket", "label": "HelloRetryRequest"},
    "psk": {"op_part": "Psk", "label": "PSK"},
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rq1_dir() -> Path:
    return repo_root() / "maude" / "scenario" / "rq1"


def rq2_dir() -> Path:
    return repo_root() / "maude" / "scenario" / "rq2"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def pascal(value: str) -> str:
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))


def op_suffix_for_cve(case_id: str) -> str:
    return "Cve" + "".join(part for part in case_id if part.isdigit())


def label_step(label: str) -> str:
    return f"ruleLabel('{label})"


def protocol_op_part(protocol: str) -> str:
    if protocol == "tls12":
        return "Tls12"
    if protocol == "tls13":
        return "Tls13"
    raise ValueError(f"unsupported protocol for bucket op: {protocol}")


def category_for_source_id(source_id: str) -> str:
    if source_id.startswith("tls12-"):
        return "5246"
    if "psk" in source_id:
        return "psk"
    if "hrr" in source_id:
        return "hrr"
    return "8446"


def bucket_id(protocol: str, category: str, pattern: str) -> str:
    return f"{protocol}-{category}-{pattern.lower()}"


def bucket_op_part(protocol: str, category: str, pattern: str) -> str:
    return f"{protocol_op_part(protocol)}{CATEGORY_INFO[category]['op_part']}{pattern}"


def bucket_base(protocol: str, category: str, pattern: str) -> str:
    return f"rq2{bucket_op_part(protocol, category, pattern)}"


@dataclass(frozen=True)
class SourceInfo:
    source_id: str
    source_file: str
    source_module: str
    requirements_file: str


SOURCE_INFO: dict[str, SourceInfo] = {
    "tls12-core": SourceInfo(
        "tls12-core",
        "maude/scenario/rfc/5246-core.maude",
        "RFC-5246-CORE",
        "maude/requirements/5246-base.maude",
    ),
    "tls12-additional": SourceInfo(
        "tls12-additional",
        "maude/scenario/rfc-additional/5246-core.maude",
        "RFC-5246-CORE-ADDITIONAL",
        "maude/requirements/5246-base.maude",
    ),
    "tls13-core": SourceInfo(
        "tls13-core",
        "maude/scenario/rfc/8446-core.maude",
        "RFC-8446-CORE",
        "maude/requirements/8446-base.maude",
    ),
    "tls13-hrr": SourceInfo(
        "tls13-hrr",
        "maude/scenario/rfc/hrr.maude",
        "RFC-HRR",
        "maude/requirements/8446-base.maude",
    ),
    "tls13-psk": SourceInfo(
        "tls13-psk",
        "maude/scenario/rfc/psk.maude",
        "RFC-PSK",
        "maude/requirements/8446-base.maude",
    ),
    "tls13-additional-core": SourceInfo(
        "tls13-additional-core",
        "maude/scenario/rfc-additional/8446-core.maude",
        "RFC-8446-CORE-ADDITIONAL",
        "maude/requirements/8446-base.maude",
    ),
    "tls13-additional-hrr": SourceInfo(
        "tls13-additional-hrr",
        "maude/scenario/rfc-additional/hrr.maude",
        "RFC-HRR-ADDITIONAL",
        "maude/requirements/8446-base.maude",
    ),
    "tls13-additional-psk": SourceInfo(
        "tls13-additional-psk",
        "maude/scenario/rfc-additional/psk.maude",
        "RFC-8446-ADDITIONAL",
        "maude/requirements/8446-base.maude",
    ),
}


def cve_specs() -> list[dict[str, object]]:
    return [
        {
            "case_id": "cve-2020-24613",
            "cve": "CVE-2020-24613",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2020-24613.maude",
            "cve_source_module": "CVE-2020-24613",
            "initial_cwa": "initialCWA24613",
            "init_conf": "initConf24613",
            "exploit_bds_op": "wolfSSLAcceptsPrematureFinished24613",
            "source_property_op": "exploitCompletes24613",
            "prefix_steps": [
                label_step("cve24613-server-omits-certificate-request"),
                label_step("cve24613-skip-server-certificate"),
                label_step("cve24613-skip-server-certificate-verify"),
                label_step("buildServerFinishedV3"),
                label_step("cve24613-client-state-skips-server-auth"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F4", "F5"],
            "count_rule": "F4/F5 omissions and acceptance guards are counted as one concrete failing trigger.",
            "notes": "Server authentication bypass with skipped Certificate and CertificateVerify.",
        },
        {
            "case_id": "cve-2021-3336",
            "cve": "CVE-2021-3336",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2021-3336.maude",
            "cve_source_module": "CVE-2021-3336",
            "initial_cwa": "initialCWA3336",
            "init_conf": "initConf3336",
            "exploit_bds_op": "wolfSSLAcceptsMissingCVKey3336",
            "source_property_op": "exploitCompletes3336",
            "prefix_steps": [
                label_step("cve3336-use-ecdsa-cv-with-rsa-cert"),
                label_step("cve3336-wolfssl-accept-missing-cv-key"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3", "F5"],
            "count_rule": "The current CVE model fixes one malformed CertificateVerify algorithm value.",
            "notes": "CertificateVerify key/algorithm mismatch accepted by the target.",
        },
        {
            "case_id": "cve-2021-3449",
            "cve": "CVE-2021-3449",
            "library": "OpenSSL",
            "protocol": "tls12",
            "aggregation_protocol": "tls12",
            "protocol_version": "TLS-12",
            "final_version": "v2",
            "cve_source_file": "../cve/cve-2021-3449.maude",
            "cve_source_module": "CVE-2021-3449",
            "initial_cwa": "initialCWA3449",
            "init_conf": "initConf3449",
            "exploit_bds_op": "sigAlgsCertOnlyRenegotiation3449",
            "source_property_op": "renegotiationCompletes3449",
            "prefix_steps": [
                "(ruleLabel('processServerFinishedV2) and appliedNode(client))",
                label_step("cve3449-renego-sigalgs-cert-only"),
                "(ruleLabel('processClientHelloV2) and appliedNode(server) and featureMap(@secureRenegotiation |-> av[true]))",
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F1", "F2"],
            "count_rule": "One modeled renegotiation ClientHello adds signature_algorithms_cert while omitting signature_algorithms.",
            "notes": "Handshake-success renegotiation case; the CVE module has no separate target-skip BDS.",
        },
        {
            "case_id": "cve-2022-25638",
            "cve": "CVE-2022-25638",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2022-25638.maude",
            "cve_source_module": "CVE-2022-25638",
            "initial_cwa": "initialCWA25638",
            "init_conf": "initConf25638",
            "exploit_bds_op": "wolfSSLAcceptsMismatchedCV25638",
            "source_property_op": "exploitCompletes25638",
            "prefix_steps": [
                label_step("cve25638-set-ecdsa-cv-algorithm-with-rsa-cert"),
                label_step("cve25638-wolfssl-accept-mismatched-cv"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3", "F5"],
            "count_rule": "The current CVE model fixes one mismatched CertificateVerify algorithm value.",
            "notes": "CertificateVerify algorithm/certificate mismatch accepted by the target.",
        },
        {
            "case_id": "cve-2022-25640",
            "cve": "CVE-2022-25640",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2022-25640.maude",
            "cve_source_module": "CVE-2022-25640",
            "initial_cwa": "initialCWA25640",
            "init_conf": "initConf25640",
            "exploit_bds_op": "wolfSSLAcceptsOmittedClientCV25640",
            "source_property_op": "exploitCompletes25640",
            "prefix_steps": [
                label_step("cve25640-client-omits-certificate-verify"),
                label_step("cve25640-wolfssl-accept-client-auth-without-cv"),
                label_step("processClientFinishedV3"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F4", "F5"],
            "count_rule": "Omitting the required client CertificateVerify is one concrete F4 trigger.",
            "notes": "Client-auth CertificateVerify omission accepted by the target.",
        },
        {
            "case_id": "cve-2022-39173",
            "cve": "CVE-2022-39173",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2022-39173.maude",
            "cve_source_module": "CVE-2022-39173",
            "initial_cwa": "initialCWA39173",
            "init_conf": "initConf39173",
            "exploit_bds_op": "duplicateCipherSuitesHrrResumption39173",
            "source_property_op": "duplicateCipherSuitesTriggerAccepted39173",
            "prefix_steps": [
                label_step("cve39173-duplicate-resumption-cipher-suites"),
                label_step("buildHelloRetryRequestV3"),
                label_step("cve39173-duplicate-hrr-cipher-suites"),
            ],
            "test_case_failures_static": 16,
            "failure_classes": ["F3"],
            "count_rule": "Two HRR-path duplicate cipher-suite lists, each over the four modeled TLS 1.3 cipher suites: 4 x 4.",
            "notes": "The source comment describes a crash trigger, but the modeled property reaches V3 closed.",
        },
        {
            "case_id": "cve-2023-3724",
            "cve": "CVE-2023-3724",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2023-3724.maude",
            "cve_source_module": "CVE-2023-3724",
            "initial_cwa": "initialCWA3724",
            "init_conf": "initConf3724",
            "exploit_bds_op": "wolfSSLAcceptsNoPskNoKeyShare3724",
            "source_property_op": "exploitCompletes3724",
            "prefix_steps": [
                label_step("cve3724-omit-server-key-share"),
                label_step("cve3724-wolfssl-skip-key-share-check"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F2", "F5"],
            "count_rule": "Missing required ServerHello key_share is one F2 trigger.",
            "notes": "PSK-DHE ServerHello without key_share accepted by the target.",
        },
        {
            "case_id": "cve-2024-5814",
            "cve": "CVE-2024-5814",
            "library": "wolfSSL",
            "protocol": "tls12",
            "aggregation_protocol": "tls12",
            "protocol_version": "TLS-12",
            "final_version": "v2",
            "cve_source_file": "../cve/cve-2024-5814.maude",
            "cve_source_module": "CVE-2024-5814",
            "initial_cwa": "initialCWA5814",
            "init_conf": "initConf5814",
            "exploit_bds_op": "wolfSSLAcceptsUnofferedCipher5814",
            "source_property_op": "exploitCompletes5814",
            "prefix_steps": [
                label_step("cve5814-select-unoffered-cipher"),
                label_step("cve5814-wolfssl-skip-cipher-check"),
                "(N1 . CI . @selectedCipherSuite = av[TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384])",
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3", "F5"],
            "count_rule": "The current CVE model fixes one coherent unoffered TLS 1.2 cipher suite.",
            "notes": "Unoffered ServerHello cipher suite accepted by the target.",
        },
        {
            "case_id": "cve-2025-11933",
            "cve": "CVE-2025-11933",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2025-11933.maude",
            "cve_source_module": "CVE-2025-11933",
            "initial_cwa": "initialCWA11933",
            "init_conf": "initConf11933",
            "exploit_bds_op": "wolfSSLAcceptsDuplicateCKS11933",
            "source_property_op": "exploitCompletes11933",
            "prefix_steps": [
                label_step("cve11933-duplicate-cks-extension"),
                label_step("cve11933-wolfssl-skip-cks-duplicate-check"),
            ],
            "test_case_failures_static": 2,
            "failure_classes": ["F1", "F5"],
            "count_rule": "Duplicate client_key_share extension over the modeled boolean CKS values: true or false.",
            "notes": "Duplicate extension accepted by the target.",
        },
        {
            "case_id": "cve-2025-11934",
            "cve": "CVE-2025-11934",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2025-11934.maude",
            "cve_source_module": "CVE-2025-11934",
            "initial_cwa": "initialCWA11934",
            "init_conf": "initConf11934",
            "exploit_bds_op": "wolfSSLAcceptsCV11934",
            "source_property_op": "exploitCompletes11934",
            "prefix_steps": [
                label_step("cve11934-use-ecdsa-sha256-cv"),
                label_step("cve11934-wolfssl-accept-cv"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3", "F5"],
            "count_rule": "The current CVE model fixes one downgraded CertificateVerify algorithm value.",
            "notes": "CertificateVerify downgrade accepted by the target.",
        },
        {
            "case_id": "cve-2025-11935",
            "cve": "CVE-2025-11935",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2025-11935.maude",
            "cve_source_module": "CVE-2025-11935",
            "initial_cwa": "initialCWA11935",
            "init_conf": "initConf11935",
            "exploit_bds_op": "wolfSSLAcceptsPskOnly11935",
            "source_property_op": "exploitCompletes11935",
            "prefix_steps": [
                label_step("cve11935-omit-server-key-share"),
                label_step("cve11935-wolfssl-skip-key-share-check"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F2", "F5"],
            "count_rule": "Missing required ServerHello key_share is one F2 trigger.",
            "notes": "PSK-DHE ServerHello without key_share accepted by the target.",
        },
        {
            "case_id": "cve-2025-11936",
            "cve": "CVE-2025-11936",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2025-11936.maude",
            "cve_source_module": "CVE-2025-11936",
            "initial_cwa": "initialCWA11936",
            "init_conf": "initConf11936",
            "exploit_bds_op": "wolfSSLAcceptsDuplicateKeyShare11936",
            "source_property_op": "exploitCompletes11936",
            "prefix_steps": [
                label_step("cve11936-duplicate-client-key-share"),
                label_step("cve11936-wolfssl-skip-duplicate-key-share-check"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3", "F5"],
            "count_rule": "The current CVE model fixes one duplicate key_share group value.",
            "notes": "Duplicate ClientHello key_share accepted by the target.",
        },
        {
            "case_id": "cve-2025-12889",
            "cve": "CVE-2025-12889",
            "library": "wolfSSL",
            "protocol": "tls12",
            "aggregation_protocol": "tls12",
            "protocol_version": "TLS-12",
            "final_version": "v2",
            "cve_source_file": "../cve/cve-2025-12889.maude",
            "cve_source_module": "CVE-2025-12889",
            "initial_cwa": "initialCWA12889",
            "init_conf": "initConf12889",
            "exploit_bds_op": "wolfSSLAcceptsCV12889",
            "source_property_op": "exploitCompletes12889",
            "prefix_steps": [
                label_step("cve12889-use-dsa-sha1-cv"),
                label_step("cve12889-wolfssl-accept-cv"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3", "F5"],
            "count_rule": "The current CVE model fixes one malformed TLS 1.2 CertificateVerify algorithm value.",
            "notes": "TLS 1.2 CertificateVerify algorithm accepted by the target.",
        },
        {
            "case_id": "cve-2026-25834",
            "cve": "CVE-2026-25834",
            "library": "Mbed TLS",
            "protocol": "tls12",
            "aggregation_protocol": "tls12",
            "protocol_version": "TLS-12",
            "final_version": "v2",
            "cve_source_file": "../cve/cve-2026-25834.maude",
            "cve_source_module": "CVE-2026-25834",
            "initial_cwa": "initialCWA25834",
            "init_conf": "initConf25834",
            "exploit_bds_op": "mbedTLSAcceptsInjectedSKE25834",
            "source_property_op": "exploitCompletes25834",
            "prefix_steps": [
                label_step("cve25834-use-unoffered-ske-sigalg"),
                label_step("cve25834-mbedtls-accept-unoffered-ske-sigalg"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3", "F5"],
            "count_rule": "The current CVE model fixes one unoffered ServerKeyExchange signature algorithm.",
            "notes": "TLS 1.2 ServerKeyExchange signature algorithm accepted by the target.",
        },
        {
            "case_id": "cve-2026-3230",
            "cve": "CVE-2026-3230",
            "library": "wolfSSL",
            "protocol": "tls13",
            "aggregation_protocol": "tls13",
            "protocol_version": "TLS-13",
            "final_version": "v3",
            "cve_source_file": "../cve/cve-2026-3230.maude",
            "cve_source_module": "CVE-2026-3230",
            "initial_cwa": "initialCWA3230",
            "init_conf": "initConf3230",
            "exploit_bds_op": "wolfSSLAcceptsMissingKeyShareAfterHrr3230",
            "source_property_op": "exploitCompletes3230",
            "prefix_steps": [
                label_step("buildHelloRetryRequestV3"),
                label_step("cve3230-omit-hrr-server-key-share"),
                label_step("cve3230-wolfssl-skip-server-key-share-check"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F2", "F5"],
            "count_rule": "Missing required post-HRR ServerHello key_share is one F2 trigger.",
            "notes": "Missing HRR-selected key_share accepted by the target.",
        },
        {
            "case_id": "cve-2026-34873",
            "cve": "CVE-2026-34873",
            "library": "Mbed TLS",
            "protocol": "mixed",
            "aggregation_protocol": "mixed",
            "protocol_version": "TLS-13",
            "final_version": "v2",
            "all_deviation_protocol": "tls13",
            "cve_source_file": "../cve/cve-2026-34873.maude",
            "cve_source_module": "CVE-2026-34873",
            "initial_cwa": "initialCWA34873",
            "init_conf": "initConf34873",
            "exploit_bds_op": "mbedTLSHrrToTls12Resumption34873",
            "source_property_op": "exploitCompletes34873",
            "prefix_steps": [
                label_step("cve34873-server-hrr-to-v2-ready"),
                label_step("cve34873-client-hrr-to-v2-init"),
            ],
            "test_case_failures_static": 1,
            "failure_classes": ["F3"],
            "count_rule": "One modeled cross-version state/session transition trigger.",
            "notes": "TLS 1.3 HRR to TLS 1.2 resumption; kept as mixed for aggregation.",
        },
    ]


EXCLUDED_CVES = [
    {
        "case_id": "cve-2021-44718",
        "reason": "rejection-only wrong-side ClientHello scenario; no handshake-success exploit property",
    },
    {
        "case_id": "cve-2025-6395",
        "reason": "rejection-only HRR second ClientHello PSK removal scenario",
    },
    {
        "case_id": "cve-2026-1005",
        "reason": "application-data underflow alert/rejection scenario; exploit condition is not handshake success",
    },
    {
        "case_id": "cve-2026-1584",
        "reason": "invalid PSK binder rejection scenario; no handshake-success exploit property",
    },
    {
        "case_id": "cve-2026-2645",
        "reason": "early CertificateVerify rejection scenario; no handshake-success exploit property",
    },
]


def load_rq1_manifest() -> list[dict[str, object]]:
    manifest_path = rq1_dir() / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing RQ1 manifest: {manifest_path}")
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return list(data["jobs"])


def relabel_term(term: str, old_label: str, new_label: str) -> str:
    return re.sub(rf"'{re.escape(old_label)}(?=[\s,\}}\)])", f"'{new_label}", term)


def extract_result_term(stdout: str) -> str:
    match = RESULT_TERM_RE.search(stdout)
    if not match:
        raise ValueError(f"could not parse Maude result term:\n{stdout[-2000:]}")
    return match.group(1).strip()


def run_reduce(maude_bin: Path, source: SourceInfo, scen: int) -> str:
    script = "\n".join(
        [
            f"load {source.requirements_file}",
            f"load {source.source_file}",
            f"red in {source.source_module} : behaviorDeviationSpecification{scen} .",
            "quit",
            "",
        ]
    )
    proc = subprocess.run(
        [str(maude_bin), "-no-advise", "-no-banner"],
        input=script,
        cwd=repo_root(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Maude reduction failed for {source.source_id} scen{scen} rc={proc.returncode}\n"
            f"stdout:\n{proc.stdout[-4000:]}\nstderr:\n{proc.stderr[-4000:]}"
        )
    return extract_result_term(proc.stdout)


def render_or_expr(values: Iterable[str]) -> str:
    values = [value for value in values if value]
    if not values:
        return "anyStep"
    return " or\n     ".join(values)


def render_set_expr(values: Iterable[str]) -> str:
    values = [value for value in values if value and value != "empty"]
    if not values:
        return "empty"
    return " ,\n     ".join(values)


def build_bucket_manifest(jobs: list[dict[str, object]]) -> list[dict[str, object]]:
    entries: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for job in jobs:
        protocol = str(job["protocol"])
        pattern = str(job["pattern"])
        category = category_for_source_id(str(job["source_id"]))
        entries[(protocol, category, pattern)].append(job)

    buckets: list[dict[str, object]] = []
    for protocol, category, pattern in sorted(entries):
        bucket_jobs = sorted(entries[(protocol, category, pattern)], key=lambda item: str(item["job_id"]))
        base = bucket_base(protocol, category, pattern)
        buckets.append(
            {
                "bucket_id": bucket_id(protocol, category, pattern),
                "protocol": protocol,
                "aggregation_protocol": protocol,
                "protocol_version": "TLS-12" if protocol == "tls12" else "TLS-13",
                "category": category,
                "category_label": CATEGORY_INFO[category]["label"],
                "pattern": pattern,
                "set_op": f"{base}Set",
                "step_op": f"{base}Step",
                "expected_instances": sum(int(job["expected_instances"]) for job in bucket_jobs),
                "job_ids": [str(job["job_id"]) for job in bucket_jobs],
                "chunk_ids": sorted({str(job["chunk_id"]) for job in bucket_jobs}),
                "source_ids": sorted({str(job["source_id"]) for job in bucket_jobs}),
            }
        )
    return buckets


def source_label(job: dict[str, object], scen: int) -> str:
    return f"rq2-{job['chunk_id']}-{str(job['pattern']).lower()}-scen{scen}"


def build_all_deviation_catalog(
    jobs: list[dict[str, object]],
    maude_bin: Path,
) -> tuple[str, dict[str, object]]:
    by_chunk_pattern: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for job in jobs:
        by_chunk_pattern[(str(job["chunk_id"]), str(job["pattern"]))].append(job)

    reduce_cache: dict[tuple[str, int], str] = {}
    chunk_entries: dict[str, dict[str, object]] = defaultdict(lambda: {"jobs": [], "protocol": None})
    bucket_entries: dict[tuple[str, str, str], dict[str, object]] = defaultdict(
        lambda: {"jobs": [], "protocol": None, "category": None, "pattern": None}
    )
    all_deviation_counts = {"tls12": 0, "tls13": 0, "total": 0}

    lines: list[str] = [
        "--- Generated by scripts/generate_rq2_modules.py; do not edit by hand.",
        "load common.maude",
        "",
        "smod RQ2-ALL-DEVIATIONS is",
        "  protecting RQ2-COMMON .",
        "",
    ]

    for job in sorted(jobs, key=lambda item: (str(item["protocol"]), str(item["chunk_id"]), str(item["pattern"]))):
        chunk_id = str(job["chunk_id"])
        pattern = str(job["pattern"])
        protocol = str(job["protocol"])
        source = SOURCE_INFO[str(job["source_id"])]
        base = f"rq2{pascal(chunk_id)}{pattern}"
        labels: list[str] = []
        terms: list[str] = []
        for scen in list(job["scens"]):
            scen_int = int(scen)
            cache_key = (source.source_id, scen_int)
            if cache_key not in reduce_cache:
                reduce_cache[cache_key] = run_reduce(maude_bin, source, scen_int)
            label = source_label(job, scen_int)
            labels.append(label)
            terms.append(relabel_term(reduce_cache[cache_key], f"scen{scen_int}", label))

        label_exprs = [f"ruleLabel('{label})" for label in labels]
        lines.extend(
            [
                f"  --- {job['job_id']} ({job['expected_instances']} instances)",
                f"  op {base}Set : -> Set{{BehaviorDVSpec}} .",
                f"  eq {base}Set =",
                f"     {render_set_expr(terms)} .",
                "",
                f"  op {base}Step : -> StepProperty .",
                f"  eq {base}Step =",
                f"     {render_or_expr(label_exprs)} .",
                "",
            ]
        )
        set_op = f"{base}Set"
        step_op = f"{base}Step"
        expected = int(job["expected_instances"])
        chunk_entries[chunk_id]["jobs"].append({"pattern": pattern, "set_op": set_op, "step_op": step_op})
        chunk_entries[chunk_id]["protocol"] = protocol
        category = category_for_source_id(str(job["source_id"]))
        bucket_key = (protocol, category, pattern)
        bucket_entries[bucket_key]["jobs"].append(
            {
                "job_id": str(job["job_id"]),
                "chunk_id": chunk_id,
                "source_id": str(job["source_id"]),
                "set_op": set_op,
                "step_op": step_op,
                "expected_instances": expected,
            }
        )
        bucket_entries[bucket_key]["protocol"] = protocol
        bucket_entries[bucket_key]["category"] = category
        bucket_entries[bucket_key]["pattern"] = pattern
        all_deviation_counts[protocol] += expected
        all_deviation_counts["total"] += expected

    protocol_chunks: dict[str, list[str]] = defaultdict(list)
    for chunk_id, entry in sorted(chunk_entries.items()):
        base = f"rq2{pascal(chunk_id)}AllDeviation"
        set_ops = [str(item["set_op"]) for item in entry["jobs"]]
        step_ops = [str(item["step_op"]) for item in entry["jobs"]]
        lines.extend(
            [
                f"  --- {chunk_id} all P1-P5 deviations",
                f"  op {base}Set : -> Set{{BehaviorDVSpec}} .",
                f"  eq {base}Set =",
                f"     {render_set_expr(set_ops)} .",
                "",
                f"  op {base}Step : -> StepProperty .",
                f"  eq {base}Step =",
                f"     {render_or_expr(step_ops)} .",
                "",
            ]
        )
        protocol_chunks[str(entry["protocol"])].append(base)

    for protocol, category, pattern in sorted(bucket_entries):
        entry = bucket_entries[(protocol, category, pattern)]
        base = bucket_base(protocol, category, pattern)
        jobs_for_bucket = list(entry["jobs"])
        expected = sum(int(item["expected_instances"]) for item in jobs_for_bucket)
        set_ops = [str(item["set_op"]) for item in jobs_for_bucket]
        step_ops = [str(item["step_op"]) for item in jobs_for_bucket]
        lines.extend(
            [
                f"  --- {bucket_id(protocol, category, pattern)} deviations ({expected} instances)",
                f"  op {base}Set : -> Set{{BehaviorDVSpec}} .",
                f"  eq {base}Set =",
                f"     {render_set_expr(set_ops)} .",
                "",
                f"  op {base}Step : -> StepProperty .",
                f"  eq {base}Step =",
                f"     {render_or_expr(step_ops)} .",
                "",
            ]
        )

    for protocol in ("tls12", "tls13"):
        proto_base = f"rq2{'Tls12' if protocol == 'tls12' else 'Tls13'}Rq1AllDeviation"
        chunk_bases = protocol_chunks.get(protocol, [])
        lines.extend(
            [
                f"  --- {protocol} all RQ1 deviations",
                f"  op {proto_base}Set : -> Set{{BehaviorDVSpec}} .",
                f"  eq {proto_base}Set =",
                f"     {render_set_expr([base + 'Set' for base in chunk_bases])} .",
                "",
                f"  op {proto_base}Step : -> StepProperty .",
                f"  eq {proto_base}Step =",
                f"     {render_or_expr([base + 'Step' for base in chunk_bases])} .",
                "",
                f"  op {proto_base}Star : -> ScenarioProperty .",
                f"  eq {proto_base}Star = {proto_base}Step * .",
                "",
            ]
        )

    lines.extend(["endsm", ""])
    return "\n".join(lines), all_deviation_counts


def final_state_ops(final_version: str) -> tuple[str, str]:
    if final_version == "v2":
        return "rq1TerminalStateV2", "rq1ClosedStateV2"
    if final_version == "v3":
        return "rq1TerminalStateV3", "rq1ClosedStateV3"
    raise ValueError(f"unsupported final_version: {final_version}")


def all_deviation_ops(protocol: str) -> tuple[str, str]:
    if protocol == "tls12":
        return "rq2Tls12Rq1AllDeviationSet", "rq2Tls12Rq1AllDeviationStep"
    if protocol == "tls13":
        return "rq2Tls13Rq1AllDeviationSet", "rq2Tls13Rq1AllDeviationStep"
    raise ValueError(f"unsupported all-deviation protocol: {protocol}")


def render_legacy_prefix(prefix_steps: list[str], all_step_op: str, final_op: str) -> str:
    parts = ["(anyStep *)"]
    for step in prefix_steps:
        parts.append(step)
        parts.append("(anyStep *)")
    parts.append(f"({all_step_op} *)")
    parts.append("(anyStep *)")
    parts.append(final_op)
    return " ;\n     ".join(parts)


def render_baseline_prefix(prefix_steps: list[str], final_op: str) -> str:
    parts = ["(anyStep *)"]
    for step in prefix_steps:
        parts.append(step)
        parts.append("(anyStep *)")
    parts.append(final_op)
    return " ;\n     ".join(parts)


def render_bucket_prefix(prefix_steps: list[str], bucket_step_op: str, final_op: str) -> str:
    parts = ["(anyStep *)"]
    for step in prefix_steps:
        parts.append(step)
        parts.append("(anyStep *)")
    parts.append(bucket_step_op)
    parts.append(f"((anyStep *) ; {bucket_step_op}) *")
    parts.append("(anyStep *)")
    parts.append(final_op)
    return " ;\n     ".join(parts)


def buckets_for_spec(spec: dict[str, object], buckets: list[dict[str, object]]) -> list[dict[str, object]]:
    all_proto = str(spec.get("all_deviation_protocol") or spec["protocol"])
    return [bucket for bucket in buckets if str(bucket["protocol"]) == all_proto]


def render_cve_module(spec: dict[str, object]) -> str:
    suffix = op_suffix_for_cve(str(spec["case_id"]))
    module_name = f"RQ2-{str(spec['case_id']).upper()}"
    all_proto = str(spec.get("all_deviation_protocol") or spec["protocol"])
    all_set_op, all_step_op = all_deviation_ops(all_proto)
    terminal_op, closed_op = final_state_ops(str(spec["final_version"]))
    bds_op = f"rq2{suffix}Bds"
    candidate_op = f"rq2{suffix}CandidateScenario"
    success_op = f"rq2{suffix}SuccessScenario"
    baseline_bds_op = f"rq2{suffix}BaselineBds"
    baseline_candidate_op = f"rq2{suffix}BaselineCandidateScenario"
    baseline_success_op = f"rq2{suffix}BaselineSuccessScenario"
    candidate_expr = render_legacy_prefix(list(spec["prefix_steps"]), all_step_op, terminal_op)
    success_expr = render_legacy_prefix(list(spec["prefix_steps"]), all_step_op, closed_op)
    baseline_candidate_expr = render_baseline_prefix(list(spec["prefix_steps"]), terminal_op)
    baseline_success_expr = render_baseline_prefix(list(spec["prefix_steps"]), closed_op)

    lines = [
        "--- Generated by scripts/generate_rq2_modules.py; do not edit by hand.",
        "load all-deviations.maude",
        f"load {spec['cve_source_file']}",
        "",
        f"smod {module_name} is",
        "  protecting RQ2-ALL-DEVIATIONS .",
        f"  protecting {spec['cve_source_module']} .",
        "",
        "  --- Legacy zero-or-more RQ1 deviation scenario.",
        f"  op {bds_op} : -> Set{{BehaviorDVSpec}} .",
        f"  eq {bds_op} =",
        f"     {spec['exploit_bds_op']} ,",
        f"     {all_set_op} .",
        "",
        f"  op {candidate_op} : -> ScenarioProperty .",
        f"  eq {candidate_op} =",
        f"     {candidate_expr} .",
        "",
        f"  op {success_op} : -> ScenarioProperty .",
        f"  eq {success_op} =",
        f"     {success_expr} .",
        "",
        "  --- Baseline exploit trigger with no extra RQ1 deviation.",
        f"  op {baseline_bds_op} : -> Set{{BehaviorDVSpec}} .",
        f"  eq {baseline_bds_op} = {spec['exploit_bds_op']} .",
        "",
        f"  op {baseline_candidate_op} : -> ScenarioProperty .",
        f"  eq {baseline_candidate_op} =",
        f"     {baseline_candidate_expr} .",
        "",
        f"  op {baseline_success_op} : -> ScenarioProperty .",
        f"  eq {baseline_success_op} =",
        f"     {baseline_success_expr} .",
        "",
        "  --- At-least-one extra RQ1 deviation, split by version/category/P bucket.",
    ]

    for bucket in list(spec.get("bucket_jobs", [])):
        bucket_suffix = bucket_op_part(str(bucket["protocol"]), str(bucket["category"]), str(bucket["pattern"]))
        bucket_bds_op = f"rq2{suffix}{bucket_suffix}Bds"
        bucket_candidate_op = f"rq2{suffix}{bucket_suffix}CandidateScenario"
        bucket_success_op = f"rq2{suffix}{bucket_suffix}SuccessScenario"
        bucket_set_op = str(bucket["set_op"])
        bucket_step_op = str(bucket["step_op"])
        bucket_candidate_expr = render_bucket_prefix(list(spec["prefix_steps"]), bucket_step_op, terminal_op)
        bucket_success_expr = render_bucket_prefix(list(spec["prefix_steps"]), bucket_step_op, closed_op)
        lines.extend(
            [
                "",
                f"  --- {bucket['bucket_id']} ({bucket['expected_instances']} RQ1 instances)",
                f"  op {bucket_bds_op} : -> Set{{BehaviorDVSpec}} .",
                f"  eq {bucket_bds_op} =",
                f"     {spec['exploit_bds_op']} ,",
                f"     {bucket_set_op} .",
                "",
                f"  op {bucket_candidate_op} : -> ScenarioProperty .",
                f"  eq {bucket_candidate_op} =",
                f"     {bucket_candidate_expr} .",
                "",
                f"  op {bucket_success_op} : -> ScenarioProperty .",
                f"  eq {bucket_success_op} =",
                f"     {bucket_success_expr} .",
            ]
        )

    lines.extend(["endsm", ""])
    return "\n".join(lines)


def decorate_cve_specs(specs: list[dict[str, object]], buckets: list[dict[str, object]]) -> list[dict[str, object]]:
    decorated: list[dict[str, object]] = []
    for spec in specs:
        row = dict(spec)
        suffix = op_suffix_for_cve(str(row["case_id"]))
        row["module_file"] = f"{row['case_id']}.maude"
        row["module_name"] = f"RQ2-{str(row['case_id']).upper()}"
        row["rq2_bds_op"] = f"rq2{suffix}Bds"
        row["candidate_property_op"] = f"rq2{suffix}CandidateScenario"
        row["success_property_op"] = f"rq2{suffix}SuccessScenario"
        row["baseline_bds_op"] = f"rq2{suffix}BaselineBds"
        row["baseline_candidate_property_op"] = f"rq2{suffix}BaselineCandidateScenario"
        row["baseline_success_property_op"] = f"rq2{suffix}BaselineSuccessScenario"
        bucket_jobs: list[dict[str, object]] = []
        for bucket in buckets_for_spec(row, buckets):
            bucket_suffix = bucket_op_part(str(bucket["protocol"]), str(bucket["category"]), str(bucket["pattern"]))
            bucket_jobs.append(
                {
                    **bucket,
                    "bds_op": f"rq2{suffix}{bucket_suffix}Bds",
                    "candidate_property_op": f"rq2{suffix}{bucket_suffix}CandidateScenario",
                    "success_property_op": f"rq2{suffix}{bucket_suffix}SuccessScenario",
                }
            )
        row["bucket_jobs"] = bucket_jobs
        decorated.append(row)
    return decorated


def build_manifest(
    cves: list[dict[str, object]],
    buckets: list[dict[str, object]],
    all_counts: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "rq2-manifest-v2",
        "generated_at": utc_now(),
        "all_deviation_counts": all_counts,
        "buckets": buckets,
        "cves": cves,
        "excluded": EXCLUDED_CVES,
    }


def materialized_has_bucket_ops(path: Path) -> bool:
    if not path.exists():
        return False
    return "op rq2Tls12Rfc5246P1Set" in path.read_text(encoding="utf-8", errors="replace")


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(description="Generate RQ2 Table IV modules and manifest.")
    parser.add_argument(
        "--maude-bin",
        default=str(root / "maude" / "maude" / "maude-3.5.1" / "maude"),
        help="Maude executable used to materialize RQ1 deviation sets.",
    )
    parser.add_argument(
        "--reuse-materialized",
        action="store_true",
        help="Keep an existing all-deviations.maude instead of re-materializing RQ1 deviations.",
    )
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="Write manifest and CVE modules without generating all-deviations.maude.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    maude_bin = Path(args.maude_bin).expanduser()

    out_dir = rq2_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    jobs = load_rq1_manifest()
    buckets = build_bucket_manifest(jobs)

    all_deviations_path = out_dir / "all-deviations.maude"
    can_reuse_materialized = args.reuse_materialized and materialized_has_bucket_ops(all_deviations_path)
    if not args.manifest_only and not can_reuse_materialized and not maude_bin.exists():
        raise FileNotFoundError(f"Maude executable not found: {maude_bin}")

    all_counts = {
        "tls12": sum(int(job["expected_instances"]) for job in jobs if job["protocol"] == "tls12"),
        "tls13": sum(int(job["expected_instances"]) for job in jobs if job["protocol"] == "tls13"),
        "total": sum(int(job["expected_instances"]) for job in jobs),
        "source": "maude/scenario/rq1/manifest.json",
    }
    if args.manifest_only:
        print("skipped all-deviations.maude (--manifest-only)")
    elif can_reuse_materialized:
        print("reused all-deviations.maude")
    else:
        catalog, materialized_counts = build_all_deviation_catalog(jobs, maude_bin)
        materialized_counts["source"] = "maude/scenario/rq1/manifest.json"
        all_counts = materialized_counts
        all_deviations_path.write_text(catalog, encoding="utf-8")
        print(f"wrote {all_deviations_path.relative_to(repo_root())}")

    cves = decorate_cve_specs(cve_specs(), buckets)
    for spec in cves:
        path = out_dir / str(spec["module_file"])
        path.write_text(render_cve_module(spec), encoding="utf-8")
        print(f"wrote {path.relative_to(repo_root())}")

    manifest = build_manifest(cves, buckets, all_counts)
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {manifest_path.relative_to(repo_root())} ({len(cves)} CVEs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
