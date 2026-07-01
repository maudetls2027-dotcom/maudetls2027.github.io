#!/usr/bin/env python3
"""TLS implementation bug analysis pipeline.

This pipeline separates three layers:

1. Broad automatic bug candidates.
2. Automatic RFC 5246/8446-probable candidates.
3. Manual-style triage records for the RFC-probable candidate set.

The automatic layers are deliberately broad. The final paper-facing numbers
must come from layer 3 or later source-audited refinements.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any


OUT = Path(__file__).resolve().parent

ROOT_CAUSES = [
    "missing_validation",
    "wrong_validation_predicate",
    "wrong_state_transition",
    "missing_state_transition_guard",
    "incorrect_field_construction",
    "incorrect_transcript_binding",
    "incorrect_key_schedule",
    "negotiation_logic_error",
    "wrong_error_handling",
    "legacy_cross_version_error",
]

GITHUB_REPOS = {
    "wolfSSL": "wolfSSL/wolfssl",
    "Mbed TLS": "Mbed-TLS/mbedtls",
    "OpenSSL": "openssl/openssl",
    "GnuTLS-GitHub": "gnutls/gnutls",
}

GITLAB_PROJECTS = {
    "GnuTLS": "gnutls/gnutls",
}

BUG_LABEL_RE = re.compile(r"bug|defect|regression|type[:/ -]?bug|kind[:/ -]?bug|triaged[:/ -]?bug", re.I)
SECURITY_RE = re.compile(r"\b(cve-\d{4}-\d+|ghsa-|security|vulnerab|advisory|embargo)\b", re.I)
BUG_TEXT_RE = re.compile(
    r"\b(bug|fix(?:es|ed)?|regression|crash|segfault|overflow|underflow|"
    r"leak|incorrect|wrong|invalid|failure|fail(?:s|ed)?|error|handshake|"
    r"alert|certificate|cipher|record|tls|ssl|psk|finished|key share|"
    r"serverhello|clienthello|client hello|server hello|compliance)\b",
    re.I,
)
NOT_BUG_RE = re.compile(
    r"\b(not a bug|expected behaviou?r|works as intended|invalid|user error|"
    r"configuration issue|support question|resolved: not a bug|resolved[:/ -]?wontfix)\b",
    re.I,
)
DUP_RE = re.compile(r"\bduplicate\b", re.I)

RFC_KEYWORD_RE = re.compile(
    r"\b(RFC ?5246|RFC ?8446|TLS ?1\.2|TLS ?1\.3|handshake|ClientHello|"
    r"ServerHello|Finished|CertificateVerify|certificate verify|PSK|pre.?shared.?key|"
    r"binder|key_share|key share|supported_groups|supported versions|supported_versions|"
    r"cipher suite|record layer|ChangeCipherSpec|alert|HelloRetryRequest|HRR|"
    r"KeyUpdate|early data|0-RTT|session resumption|renegotiation|CertificateRequest|"
    r"NewSessionTicket|legacy_compression|compression method)\b",
    re.I,
)
NORMATIVE_RE = re.compile(
    r"\b(MUST|MUST NOT|SHALL|SHOULD|violat|invalid|accept|reject|verify|"
    r"validate|check|alert|unexpected_message|illegal_parameter|decode_error|"
    r"missing_extension|conformance|compliance)\b",
    re.I,
)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


class CurlClient:
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.gitlab_token = os.environ.get("GITLAB_TOKEN")

    def get(self, url: str, platform: str) -> tuple[Any, dict[str, str]]:
        headers = ["User-Agent: maude-tls-attacker-bug-analysis"]
        if platform == "github":
            headers += ["Accept: application/vnd.github+json", "X-GitHub-Api-Version: 2022-11-28"]
            if self.github_token:
                headers.append(f"Authorization: Bearer {self.github_token}")
        elif platform == "gitlab":
            headers.append("Accept: application/json")
            if self.gitlab_token:
                headers.append(f"PRIVATE-TOKEN: {self.gitlab_token}")
        with tempfile.TemporaryDirectory() as tmp:
            hpath = Path(tmp) / "headers.txt"
            cmd = ["curl", "-fsSL", "--connect-timeout", "20", "--max-time", "60", "-D", str(hpath)]
            for h in headers:
                cmd += ["-H", h]
            cmd.append(url)
            for attempt in range(5):
                proc = subprocess.run(cmd, text=True, capture_output=True)
                if proc.returncode == 0:
                    meta = {}
                    for line in hpath.read_text(errors="replace").splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            meta[k.strip().lower()] = v.strip()
                    time.sleep(self.delay)
                    return json.loads(proc.stdout), meta
                stderr = proc.stderr.lower()
                if attempt < 4 and ("rate limit" in stderr or "429" in stderr or "403" in stderr):
                    time.sleep(65)
                    continue
                if attempt < 4:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise RuntimeError(f"curl failed for {url}: {proc.stderr[:800]}")
        raise RuntimeError(f"curl failed for {url}")


def labels_text(labels: Any) -> str:
    out = []
    for label in labels or []:
        out.append(str(label.get("name", "")) if isinstance(label, dict) else str(label))
    return " ".join(out)


def blob_for(item: dict[str, Any]) -> str:
    return "\n".join(
        str(item.get(k) or "")
        for k in ["title", "body", "description", "labels_text"]
    )


def storage_classification(labels: str, blob: str) -> str | None:
    if SECURITY_RE.search(labels) or SECURITY_RE.search(blob):
        return "security/advisory"
    if BUG_LABEL_RE.search(labels):
        return "direct-bug-label"
    if BUG_TEXT_RE.search(blob):
        return "bug-inferred"
    return None


def github_search(client: CurlClient, repo: str, kind: str, since: str, raw_dir: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in range(1, 11):
        q = f"repo:{repo} created:>={since[:10]} is:{kind}"
        url = "https://api.github.com/search/issues?" + urllib.parse.urlencode(
            {"q": q, "per_page": 100, "page": page, "sort": "created", "order": "asc"}
        )
        data, meta = client.get(url, "github")
        write_json(raw_dir / "github" / slug(repo) / f"{kind}_page_{page}.json", {"url": url, "meta": meta, "data": data})
        items = data.get("items", [])
        out.extend(items)
        if len(items) < 100:
            break
    return out


def gitlab_list(client: CurlClient, project: str, kind: str, since: str, raw_dir: Path) -> list[dict[str, Any]]:
    encoded = urllib.parse.quote_plus(project)
    path = "issues" if kind == "issue" else "merge_requests"
    out: list[dict[str, Any]] = []
    for page in range(1, 11):
        url = f"https://gitlab.com/api/v4/projects/{encoded}/{path}?" + urllib.parse.urlencode(
            {"created_after": since, "state": "all", "per_page": 100, "page": page}
        )
        data, meta = client.get(url, "gitlab")
        write_json(raw_dir / "gitlab" / slug(project) / f"{kind}_page_{page}.json", {"url": url, "meta": meta, "data": data})
        out.extend(data)
        if len(data) < 100:
            break
    return out


def normalize_item(library: str, source: str, platform: str, kind: str, item: dict[str, Any]) -> dict[str, Any] | None:
    labels = labels_text(item.get("labels", []))
    item = dict(item)
    item["labels_text"] = labels
    blob = blob_for(item)
    cls = storage_classification(labels, blob)
    if cls is None:
        return None
    url = item.get("html_url") or item.get("web_url") or item.get("url")
    if not url:
        return None
    state = item.get("state")
    fixed_status = "recognized_unfixed_or_open"
    if str(state).lower() in {"closed", "merged"}:
        fixed_status = "closed_or_fixed_unverified"
    if platform == "github" and kind == "pr" and str(state).lower() == "closed":
        fixed_status = "closed_pr_merge_unverified"
    if platform == "gitlab" and item.get("merged_at"):
        fixed_status = "fixed_merged_mr"
    excluded_reason = ""
    if DUP_RE.search(labels):
        excluded_reason = "duplicate"
    elif NOT_BUG_RE.search(labels) or NOT_BUG_RE.search(blob):
        excluded_reason = "not_bug_or_invalid_signal"
    rfc_auto = bool(RFC_KEYWORD_RE.search(blob) and NORMATIVE_RE.search(blob))
    return {
        "id": f"{platform}:{source}:{kind}:{item.get('number', item.get('iid', item.get('id')))}",
        "library": library,
        "source": source,
        "platform": platform,
        "kind": kind,
        "url": url,
        "title": item.get("title", ""),
        "created_at": item.get("created_at"),
        "state": state,
        "labels": labels,
        "storage_classification": cls,
        "fixed_status": fixed_status,
        "auto_rfc_probable": rfc_auto,
        "excluded_reason": excluded_reason,
        "body_excerpt": (item.get("body") or item.get("description") or "")[:1500],
    }


def infer_manual_bucket(item: dict[str, Any]) -> str:
    text = "\n".join([item["title"], item.get("labels", ""), item.get("body_excerpt", "")])
    if item.get("excluded_reason"):
        return "Not-related"
    if re.search(r"\b(RFC ?5280|RFC ?6125|RFC ?8701|RFC ?8446bis|QUIC|DTLS ?1\.3|ECH|HPKE|X\.509|OCSP|PKCS#7|PKCS#11|HTTP|build|test|doc|documentation|format|CI|AIX|MinGW|CMake|make check|fuzzer|fuzz)\b", text, re.I):
        if not re.search(r"\b(RFC ?5246|RFC ?8446|TLS ?1\.2|TLS ?1\.3|ClientHello|ServerHello|Finished|CertificateVerify|PSK|key_share|KeyUpdate|early_data|record|alert|CertificateRequest|NewSessionTicket|session_id|compression)\b", text, re.I):
            return "Not-related"
    if re.search(r"\b(RFC ?5246|RFC ?8446|MUST|SHALL|violat|compliance|conformance)\b", text, re.I):
        return "RFC-Core"
    if re.search(r"\b(TLS ?1\.2|TLS ?1\.3|ClientHello|ServerHello|Finished|CertificateVerify|PSK|key_share|KeyUpdate|early_data|record|alert|CertificateRequest|NewSessionTicket|session_id|compression|HRR|HelloRetryRequest)\b", text, re.I):
        return "RFC-probable"
    if re.search(r"\b(TLS|SSL|handshake|certificate|cipher|session|renegotiation)\b", text, re.I):
        return "TLS-Adjacent"
    return "Not-related"


def infer_rfcs(item: dict[str, Any]) -> list[str]:
    text = "\n".join([item["title"], item.get("labels", ""), item.get("body_excerpt", "")])
    rfcs = []
    if re.search(r"\b(RFC ?5246|TLS ?1\.2|renegotiation|session_id|ClientKeyExchange|ChangeCipherSpec)\b", text, re.I):
        rfcs.append("RFC5246")
    if re.search(r"\b(RFC ?8446|TLS ?1\.3|PSK|binder|key_share|supported_versions|HelloRetryRequest|HRR|KeyUpdate|early_data|0-RTT|NewSessionTicket|CertificateRequest|legacy_compression)\b", text, re.I):
        rfcs.append("RFC8446")
    if not rfcs and re.search(r"\b(handshake|record|alert|cipher suite|certificate verify|finished)\b", text, re.I):
        rfcs = ["RFC5246", "RFC8446"]
    return rfcs


def infer_root_cause(item: dict[str, Any]) -> str:
    text = "\n".join([item["title"], item.get("labels", ""), item.get("body_excerpt", "")])
    rules = [
        ("incorrect_key_schedule", r"\b(HKDF|traffic secret|key schedule|secret cleanup|derive|KDF|PRF)\b"),
        ("incorrect_transcript_binding", r"\b(transcript|Finished|CertificateVerify|verify_data|binder|signature input)\b"),
        ("legacy_cross_version_error", r"\b(legacy|TLS ?1\.2.*TLS ?1\.3|TLS ?1\.3.*TLS ?1\.2|fallback)\b"),
        ("wrong_state_transition", r"\b(state machine|state transition|message order|sequence|too early|before|required KeyUpdate|NewSessionTicket instead)\b"),
        ("missing_state_transition_guard", r"\b(state guard|unexpected_message|out of order|span key changes|two KeyUpdates)\b"),
        ("wrong_error_handling", r"\b(alert|handshake_failure|illegal_parameter|decode_error|missing_extension|wrong error|without an alert)\b"),
        ("wrong_validation_predicate", r"\b(wrong check|incorrect check|predicate|compare|mismatch|truncation|strlen|boundary)\b"),
        ("incorrect_field_construction", r"\b(extension|field|length|version|cipher suite|key_share|supported_versions|encode|construct|format|nonce|IV)\b"),
        ("negotiation_logic_error", r"\b(negotiate|selection|selected|group|cipher|version|downgrade|priority)\b"),
        ("missing_validation", r"\b(missing check|missing validation|does not validate|does not verify|not checked|accepts|accepted|reject|invalid|limit)\b"),
    ]
    for name, pat in rules:
        if re.search(pat, text, re.I):
            return name
    return "missing_validation"


def infer_expressibility(root: str, bucket: str) -> tuple[str, str]:
    if bucket not in {"RFC-Core", "RFC-probable"}:
        return "not_applicable", "Not an RFC 5246/8446 core/probable behavior bug."
    if root in {"missing_validation", "missing_state_transition_guard"}:
        return "expressible_noCheck", "Representable when the local model has a matching rfc-requirement(label[n])."
    if root in {"incorrect_field_construction"}:
        return "expressible_setM_add_remove", "Representable for modeled wire-message fields using setM/add/remove."
    if root in {"negotiation_logic_error"}:
        return "expressible_combination", "Usually needs setF for selected state plus setM/noCheck for peer input."
    if root in {"wrong_error_handling", "wrong_state_transition", "wrong_validation_predicate", "incorrect_transcript_binding", "legacy_cross_version_error"}:
        return "partially_expressible", "Partly representable, but exact predicate/state/alert/transcript behavior may need model-specific checks."
    return "requires_model_extension", "Requires additional semantics beyond current setF/noCheck/message-field operations."


def manual_triage(auto_rfc: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in auto_rfc:
        bucket = infer_manual_bucket(item)
        root = infer_root_cause(item)
        expressibility, reason = infer_expressibility(root, bucket)
        rfcs = infer_rfcs(item)
        out.append({
            **item,
            "manual_rfc_classification": bucket,
            "manual_rfc": rfcs,
            "primary_root_cause": root,
            "expressibility": expressibility,
            "expressibility_reason": reason,
            "manual_review_basis": "manual-style deterministic triage over title/body/labels/raw API metadata; source-audit required for publication claims",
        })
    return out


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = sorted({k for r in rows for k in r})
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v for k, v in row.items()})


def count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = row.get(key)
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", default="2026-01-01T00:00:00Z")
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--skip-collect", action="store_true")
    args = parser.parse_args()

    raw_dir = OUT / "raw"
    client = CurlClient(args.delay)
    candidates: list[dict[str, Any]] = []

    if not args.skip_collect:
        for library, repo in GITHUB_REPOS.items():
            for kind in ["issue", "pr"]:
                for item in github_search(client, repo, kind, args.since, raw_dir):
                    norm = normalize_item(library, repo, "github", kind, item)
                    if norm:
                        candidates.append(norm)
        for library, project in GITLAB_PROJECTS.items():
            for kind in ["issue", "mr"]:
                for item in gitlab_list(client, project, kind, args.since, raw_dir):
                    norm = normalize_item(library, project, "gitlab", kind, item)
                    if norm:
                        candidates.append(norm)
        write_json(OUT / "auto_candidates.json", candidates)
    else:
        candidates = json.loads((OUT / "auto_candidates.json").read_text(encoding="utf-8"))

    auto_rfc = [c for c in candidates if c["auto_rfc_probable"] and not c["excluded_reason"]]
    write_json(OUT / "auto_rfc_probable_candidates.json", auto_rfc)
    triaged = manual_triage(auto_rfc)
    write_json(OUT / "manual_triage_auto_rfc_probable.json", triaged)
    write_csv(OUT / "manual_triage_auto_rfc_probable.csv", triaged)

    core_prob = [r for r in triaged if r["manual_rfc_classification"] in {"RFC-Core", "RFC-probable"}]
    rfc5246 = [r for r in core_prob if "RFC5246" in r["manual_rfc"]]
    rfc8446 = [r for r in core_prob if "RFC8446" in r["manual_rfc"]]
    otherwise = [r for r in core_prob if "RFC5246" not in r["manual_rfc"] and "RFC8446" not in r["manual_rfc"]]
    counts = {
        "generated_at": now(),
        "created_at_cutoff": args.since,
        "auto_bug_candidates": len(candidates),
        "auto_rfc_probable_candidates": len(auto_rfc),
        "manual_classification_counts": count_by(triaged, "manual_rfc_classification"),
        "rfc_core_or_probable_count": len(core_prob),
        "rfc5246_count": len(rfc5246),
        "rfc8446_count": len(rfc8446),
        "otherwise_count": len(otherwise),
        "root_cause_counts_rfc_core_or_probable": count_by(core_prob, "primary_root_cause"),
        "expressibility_counts_rfc_core_or_probable": count_by(core_prob, "expressibility"),
    }
    write_json(OUT / "analysis_counts.json", counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
