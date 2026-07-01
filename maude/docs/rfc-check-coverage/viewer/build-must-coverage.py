#!/usr/bin/env python3
"""Build a statement-centered RFC MUST/MUST NOT coverage inventory and viewer.

The generated artifacts are intentionally separate from the older class-based
RFC-check viewer.  This script treats explicit uppercase MUST / MUST NOT
occurrences in RFC 5246 and RFC 8446 as the denominator seed, then derives an
initial coverage status by overlapping source lines with denominator-v1.md and
numerator-v1.md.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[4]
DOC_DIR = ROOT / "maude" / "docs" / "rfc-check-coverage"
SPEC_DIR = ROOT / "maude" / "docs" / "specs" / "tls"
VIEWER_DIR = DOC_DIR / "viewer"
RAW_DIR = VIEWER_DIR / "raw"

DENOMINATOR = DOC_DIR / "denominator-v1.md"
NUMERATOR = DOC_DIR / "numerator-v1.md"

OUT_JSON = DOC_DIR / "must-statements-v1.json"
OUT_MD = DOC_DIR / "must-statements-v1.md"
OUT_CLASS_JSON = DOC_DIR / "must-classification-v1.json"
OUT_CLASS_MD = DOC_DIR / "must-classification-v1.md"
OUT_VIEWER_JSON = VIEWER_DIR / "must-coverage-data.json"
OUT_MAPPING_REPORT = VIEWER_DIR / "mapping-report.md"

TAG_RE = re.compile(r"<[^>]+>")
MODAL_RE = re.compile(r"\bMUST NOT\b|\bMUST\b")

CLASS_LABELS = {
    "message_order": "Message order expectations",
    "extension_validity": "Extension validity",
    "negotiation_consistency": "Negotiation consistency",
    "authentication_validity": "Authentication validity",
    "cryptographic_context_validity": "Cryptographic-context validity",
    "session_resumption_post_handshake_validity": "Session/resumption/post-handshake validity",
    "others": "Others",
}

CLASS_ORDER = list(CLASS_LABELS)


@dataclass
class SourceRef:
    raw: str
    file: str
    start: int
    end: int

    def to_json(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "file": self.file,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class OldCoverageRow:
    id: str
    rfc: str
    source_refs: list[SourceRef]
    status: str
    maude_refs: list[str]


@dataclass
class TextLine:
    file: str
    no: int
    text: str
    section_id: str
    section_title: str
    block_type: str


@dataclass
class TextBlock:
    rfc: str
    file: str
    section_id: str
    section_title: str
    block_type: str
    lines: list[TextLine]


@dataclass
class Statement:
    id: str
    rfc: str
    keyword: str
    statement_text: str
    normalized_text: str
    section_id: str
    section_title: str
    source_refs: list[SourceRef]
    source_lines_raw: list[str]
    block_type: str
    context_before: str
    context_after: str
    sentence_group_id: str
    extraction_status: str
    exclusion_reason: str
    dedupe_cluster: str = ""
    canonical_candidate_id: str = ""
    class_name: str = "ALL"
    scope: str = "unclassified"
    status: str = "Not Implemented"
    coverage: str = "uncovered"
    reason_code: str = "no_existing_coverage_mapping"
    maude_refs: list[str] = field(default_factory=list)
    old_row_ids: list[str] = field(default_factory=list)
    matched_lines: int = 0
    unmatched_lines: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rfc": self.rfc,
            "keyword": self.keyword,
            "class": self.class_name,
            "classLabel": CLASS_LABELS.get(self.class_name, self.class_name),
            "scope": self.scope,
            "status": self.status,
            "coverage": self.coverage,
            "reasonCode": self.reason_code,
            "section": {
                "id": self.section_id,
                "title": self.section_title,
            },
            "text": self.statement_text,
            "normalizedText": self.normalized_text,
            "sourceRefs": [ref.to_json() for ref in self.source_refs],
            "sourceLinesRaw": self.source_lines_raw,
            "blockType": self.block_type,
            "contextBefore": self.context_before,
            "contextAfter": self.context_after,
            "sentenceGroupId": self.sentence_group_id,
            "dedupeCluster": self.dedupe_cluster,
            "canonicalCandidateId": self.canonical_candidate_id,
            "extractionStatus": self.extraction_status,
            "exclusionReason": self.exclusion_reason,
            "maudeRefs": self.maude_refs,
            "oldCoverageRows": self.old_row_ids,
            "match": {
                "matchedLines": self.matched_lines,
                "unmatchedLines": self.unmatched_lines,
            },
        }


def split_md_row(line: str) -> list[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]

    cells: list[str] = []
    current: list[str] = []
    in_code = False
    for ch in text:
        if ch == "`":
            in_code = not in_code
            current.append(ch)
        elif ch == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    cells.append("".join(current).strip())
    return cells


def strip_inline_code(value: str) -> str:
    value = value.strip()
    if value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value


def normalize_old_status(value: str) -> str:
    value = re.sub(r"\s+", " ", strip_inline_code(value)).strip().lower()
    if value == "implemented":
        return "Implemented"
    if value == "partial":
        return "Partially Implemented"
    if value == "not implemented":
        return "Not Implemented"
    return value


def parse_source_refs(source_cell: str, rfc: str) -> list[SourceRef]:
    tokens = re.findall(r"`([^`]+)`", source_cell)
    refs: list[SourceRef] = []
    last_file: str | None = None
    for token in tokens:
        token = token.strip()
        explicit = re.fullmatch(r"(rfc\d+\.txt):(\d+)(?:-(\d+))?", token)
        shorthand = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
        if explicit:
            file_name = explicit.group(1)
            start = int(explicit.group(2))
            end = int(explicit.group(3) or start)
            last_file = file_name
        elif shorthand and last_file:
            file_name = last_file
            start = int(shorthand.group(1))
            end = int(shorthand.group(2) or start)
        else:
            raise ValueError(f"Cannot parse source ref {token!r}")

        if file_name != f"rfc{rfc}.txt":
            raise ValueError(f"Source ref {token!r} disagrees with RFC {rfc}")
        refs.append(SourceRef(raw=token, file=file_name, start=start, end=end))
    return refs


def parse_old_coverage() -> list[OldCoverageRow]:
    source_by_id: dict[str, tuple[str, list[SourceRef]]] = {}
    for line_no, line in enumerate(DENOMINATOR.read_text(encoding="utf-8").splitlines(), start=1):
        if not re.match(r"^\|\s*`\d{4}-[A-Z]+-\d+`\s*\|", line):
            continue
        cells = split_md_row(line)
        row_id = strip_inline_code(cells[0])
        rfc = cells[1].strip()
        source_by_id[row_id] = (rfc, parse_source_refs(cells[3], rfc))

    rows: list[OldCoverageRow] = []
    for line_no, line in enumerate(NUMERATOR.read_text(encoding="utf-8").splitlines(), start=1):
        if not re.match(r"^\|\s*`\d{4}-[A-Z]+-\d+`\s*\|", line):
            continue
        cells = split_md_row(line)
        row_id = strip_inline_code(cells[0])
        if row_id not in source_by_id:
            raise ValueError(f"Numerator row {row_id} has no denominator source")
        rfc, source_refs = source_by_id[row_id]
        rows.append(
            OldCoverageRow(
                id=row_id,
                rfc=rfc,
                source_refs=source_refs,
                status=normalize_old_status(cells[1]),
                maude_refs=re.findall(r"`([^`]+)`", cells[2]),
            )
        )
    return rows


def read_spec_lines(rfc: str) -> list[str]:
    # Keep line numbering identical to the local RFC text files.  splitlines()
    # treats form-feed page breaks as line breaks and shifts citations.
    return (SPEC_DIR / f"rfc{rfc}.txt").read_text(encoding="utf-8", errors="replace").split("\n")


def is_page_artifact(line: str, rfc: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if stripped == "\x0c":
        return True
    stripped = stripped.lstrip("\x0c").strip()
    if re.match(rf"^RFC {rfc}\s+TLS\s+August \d{{4}}$", stripped):
        return True
    if re.search(r"\[Page \d+\]$", stripped):
        return True
    return False


def body_start_line(lines: list[str]) -> int:
    for idx, line in enumerate(lines, start=1):
        if re.match(r"^1\.\s+Introduction\s*$", line):
            return idx
    raise ValueError("Could not find section 1 Introduction")


def parse_heading(line: str) -> tuple[str, str] | None:
    if line[:1].isspace():
        return None
    stripped = line.strip()
    match = re.match(r"^((?:\d+(?:\.\d+)*|[A-Z](?:\.\d+)*|Appendix [A-Z])\.)\s+(.+?)\s*$", stripped)
    if not match:
        return None
    section_id = match.group(1).rstrip(".")
    title = match.group(2).strip()
    if title.endswith("[Page"):
        return None
    if "." * 3 in title:
        return None
    return section_id, title


def block_type_for_section(section_id: str, section_title: str, lines: list[TextLine]) -> str:
    if section_title.lower().startswith("requirements terminology") or section_title.lower().startswith("conventions and terminology"):
        joined = " ".join(line.text.strip() for line in lines)
        if "MUST" in joined:
            return "terminology"
    if section_id in {"1.2"} and "Major Differences" in section_title:
        return "summary"
    if re.match(r"^[A-Z](?:\.|$)|^Appendix [A-Z]$", section_id):
        return "appendix"
    stripped = [line.text.rstrip() for line in lines if line.text.strip()]
    if stripped and sum(1 for line in stripped if line.startswith("      ") or line.startswith("         ")) >= max(1, len(stripped) // 2):
        if any(token in " ".join(stripped) for token in ("{", "}", "enum", "struct", "opaque", "uint")):
            return "code"
    return "prose"


def iter_blocks(rfc: str) -> list[TextBlock]:
    lines = read_spec_lines(rfc)
    start = body_start_line(lines)
    file_name = f"rfc{rfc}.txt"
    section_id = "1"
    section_title = "Introduction"
    pending: list[TextLine] = []
    blocks: list[TextBlock] = []

    def flush() -> None:
        nonlocal pending
        if not pending:
            return
        block_type = block_type_for_section(section_id, section_title, pending)
        for line in pending:
            line.block_type = block_type
        blocks.append(
            TextBlock(
                rfc=rfc,
                file=file_name,
                section_id=section_id,
                section_title=section_title,
                block_type=block_type,
                lines=pending,
            )
        )
        pending = []

    for line_no in range(start, len(lines) + 1):
        raw = lines[line_no - 1]
        if is_page_artifact(raw, rfc):
            flush()
            continue

        clean = raw.lstrip("\x0c")
        heading = parse_heading(clean)
        if heading:
            flush()
            section_id, section_title = heading
            continue

        pending.append(
            TextLine(
                file=file_name,
                no=line_no,
                text=clean,
                section_id=section_id,
                section_title=section_title,
                block_type="",
            )
        )
    flush()
    return blocks


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def text_fingerprint(text: str) -> str:
    normalized = normalize_text(text).lower().replace("``", "\"").replace("''", "\"")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def join_block(block: TextBlock) -> tuple[str, list[int]]:
    parts: list[str] = []
    char_lines: list[int] = []
    for text_line in block.lines:
        text = text_line.text.strip()
        if not text:
            continue
        if parts:
            parts.append(" ")
            char_lines.append(text_line.no)
        parts.append(text)
        char_lines.extend([text_line.no] * len(text))
    return "".join(parts), char_lines


def sentence_ranges(text: str) -> list[tuple[int, int]]:
    if not text:
        return []
    ranges: list[tuple[int, int]] = []
    start = 0
    protected = {"e.g.", "i.e.", "i. e.", "e. g.", "vs.", "Mr.", "Ms.", "Dr."}
    for idx, ch in enumerate(text):
        if ch not in ".!?":
            continue
        window = text[max(0, idx - 8) : idx + 1]
        if any(window.endswith(item) for item in protected):
            continue
        if idx > 0 and idx + 1 < len(text) and text[idx - 1].isdigit() and text[idx + 1].isdigit():
            continue
        next_idx = idx + 1
        while next_idx < len(text) and text[next_idx] in " \t'\"”)]":
            next_idx += 1
        if next_idx < len(text) and not re.match(r"[A-Z0-9\[(]", text[next_idx]):
            continue
        end = idx + 1
        while end < len(text) and text[end] in "'\"”)]":
            end += 1
        ranges.append((start, end))
        start = next_idx
    if start < len(text):
        ranges.append((start, len(text)))
    return [(s, e) for s, e in ranges if text[s:e].strip()]


def line_spans_for_lines(file_name: str, line_numbers: list[int]) -> list[SourceRef]:
    if not line_numbers:
        return []
    spans: list[SourceRef] = []
    sorted_lines = sorted(set(line_numbers))
    start = prev = sorted_lines[0]
    for line_no in sorted_lines[1:]:
        if line_no == prev + 1:
            prev = line_no
            continue
        raw = f"{file_name}:{start}" if start == prev else f"{file_name}:{start}-{prev}"
        spans.append(SourceRef(raw=raw, file=file_name, start=start, end=prev))
        start = prev = line_no
    raw = f"{file_name}:{start}" if start == prev else f"{file_name}:{start}-{prev}"
    spans.append(SourceRef(raw=raw, file=file_name, start=start, end=prev))
    return spans


def extract_statements() -> list[Statement]:
    statements: list[Statement] = []
    counters = {"5246": 0, "8446": 0}
    group_counters = {"5246": 0, "8446": 0}

    for rfc in ("5246", "8446"):
        spec_lines = read_spec_lines(rfc)
        for block in iter_blocks(rfc):
            text, char_lines = join_block(block)
            if not text:
                continue
            ranges = sentence_ranges(text)
            for range_idx, (start, end) in enumerate(ranges):
                sentence = normalize_text(text[start:end])
                modal_matches = list(MODAL_RE.finditer(sentence))
                if not modal_matches:
                    continue
                group_counters[rfc] += 1
                sentence_group_id = f"{rfc}-SENT-{group_counters[rfc]:04d}"
                line_numbers = sorted(set(char_lines[start:end]))
                source_refs = line_spans_for_lines(block.file, line_numbers)
                source_lines_raw = [spec_lines[line_no - 1] for line_no in line_numbers]
                context_before = normalize_text(text[ranges[range_idx - 1][0] : ranges[range_idx - 1][1]]) if range_idx > 0 else ""
                context_after = normalize_text(text[ranges[range_idx + 1][0] : ranges[range_idx + 1][1]]) if range_idx + 1 < len(ranges) else ""
                extraction_status = "included"
                exclusion_reason = ""
                if block.block_type == "terminology":
                    extraction_status = "excluded"
                    exclusion_reason = "requirements_terminology_boilerplate"

                for modal in modal_matches:
                    counters[rfc] += 1
                    keyword = modal.group(0)
                    statements.append(
                        Statement(
                            id=f"{rfc}-MUST-{counters[rfc]:04d}",
                            rfc=rfc,
                            keyword=keyword,
                            statement_text=sentence,
                            normalized_text=normalize_text(sentence),
                            section_id=block.section_id,
                            section_title=block.section_title,
                            source_refs=source_refs,
                            source_lines_raw=source_lines_raw,
                            block_type=block.block_type,
                            context_before=context_before,
                            context_after=context_after,
                            sentence_group_id=sentence_group_id,
                            extraction_status=extraction_status,
                            exclusion_reason=exclusion_reason,
                        )
                    )
    assign_dedupe(statements)
    return statements


def assign_dedupe(statements: list[Statement]) -> None:
    clusters: dict[tuple[str, str, str], list[Statement]] = {}
    for statement in statements:
        key = (statement.rfc, statement.keyword, text_fingerprint(statement.statement_text))
        clusters.setdefault(key, []).append(statement)

    for idx, members in enumerate(clusters.values(), start=1):
        if len(members) == 1:
            continue
        cluster_id = f"DEDUP-{idx:04d}"
        canonical = choose_canonical(members)
        for statement in members:
            statement.dedupe_cluster = cluster_id
            statement.canonical_candidate_id = canonical.id


def choose_canonical(members: list[Statement]) -> Statement:
    def score(statement: Statement) -> tuple[int, int]:
        block_penalty = {
            "prose": 0,
            "summary": 1,
            "appendix": 2,
            "code": 3,
            "terminology": 9,
        }.get(statement.block_type, 4)
        first_line = min(ref.start for ref in statement.source_refs)
        return block_penalty, first_line

    return sorted(members, key=score)[0]


CLASSIFICATION_SPECS = {
    "5246": {
        "message_order": [
            "0009-0010",
            "0017",
            "0044",
            "0046",
            "0102-0105",
            "0112-0113",
        ],
        "extension_validity": [
            "0054-0056",
            "0059-0063",
            "0065-0067",
        ],
        "negotiation_consistency": [
            "0049",
            "0052-0053",
            "0064",
            "0085-0086",
            "0106-0107",
            "0121-0126",
        ],
        "authentication_validity": [
            "0004",
            "0043",
            "0068-0083",
            "0087-0101",
            "0114-0115",
        ],
        "cryptographic_context_validity": [
            "0030-0031",
            "0047",
            "0108-0109",
            "0116-0118",
        ],
        "session_resumption_post_handshake_validity": [
            "0032",
            "0034-0035",
            "0045",
            "0050-0051",
            "0058",
            "0136",
        ],
        "others": [
            "0001-0003",
            "0005-0008",
            "0011-0016",
            "0018-0029",
            "0033",
            "0036-0042",
            "0048",
            "0057",
            "0084",
            "0110-0111",
            "0119-0120",
            "0127-0135",
            "0137-0138",
        ],
    },
    "8446": {
        "message_order": [
            "0004",
            "0007-0008",
            "0013",
            "0037",
            "0048-0049",
            "0078",
            "0150-0151",
            "0154",
            "0162",
            "0189",
            "0200-0203",
            "0223-0227",
            "0229-0234",
            "0259",
            "0266-0271",
            "0313",
        ],
        "extension_validity": [
            "0025",
            "0035-0036",
            "0044-0045",
            "0055-0061",
            "0069-0070",
            "0072",
            "0076-0077",
            "0080-0081",
            "0095",
            "0102",
            "0123",
            "0147-0148",
            "0152-0153",
            "0156-0157",
            "0163-0164",
            "0170-0174",
            "0210",
            "0286-0292",
            "0297",
            "0323",
        ],
        "negotiation_consistency": [
            "0003",
            "0005",
            "0009",
            "0011-0012",
            "0017",
            "0021-0024",
            "0028-0031",
            "0033-0034",
            "0038-0042",
            "0046-0047",
            "0050-0054",
            "0062-0068",
            "0071",
            "0073-0075",
            "0090",
            "0103-0113",
            "0115-0118",
            "0285",
            "0295-0296",
            "0299",
            "0304",
            "0307-0311",
            "0314-0322",
        ],
        "authentication_validity": [
            "0079",
            "0082-0089",
            "0091-0094",
            "0096-0100",
            "0159-0161",
            "0165-0169",
            "0175-0188",
            "0190-0194",
            "0284",
            "0298",
        ],
        "cryptographic_context_validity": [
            "0135-0136",
            "0141-0142",
            "0155",
            "0195-0199",
            "0244",
            "0247",
            "0250-0251",
            "0253",
            "0256-0257",
            "0273-0275",
            "0325",
        ],
        "session_resumption_post_handshake_validity": [
            "0006",
            "0010",
            "0014-0016",
            "0018-0020",
            "0032",
            "0043",
            "0101",
            "0114",
            "0119-0122",
            "0124-0132",
            "0134",
            "0137-0140",
            "0143-0146",
            "0149",
            "0158",
            "0204-0209",
            "0211-0222",
            "0260",
            "0277-0278",
            "0280-0282",
            "0312",
            "0324",
            "0326-0330",
        ],
        "others": [
            "0001-0002",
            "0026-0027",
            "0133",
            "0228",
            "0235-0243",
            "0245-0246",
            "0248-0249",
            "0252",
            "0254-0255",
            "0258",
            "0261-0265",
            "0272",
            "0276",
            "0279",
            "0283",
            "0293-0294",
            "0300-0303",
            "0305-0306",
        ],
    },
}


MANUAL_STATEMENT_OVERRIDES = {
    "5246-MUST-0051": {
        "text": (
            "If the session_id field is not empty (implying a session "
            "resumption request), it MUST include the compression_method "
            "from that session."
        ),
        "source_refs": [
            ("rfc5246.txt", 2293, 2294),
            ("rfc5246.txt", 2303, 2303),
        ],
    },
}


MANUAL_COVERAGE_OVERRIDES = {
    "8446-MUST-0079": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_key_type_checked_against_signature_algorithm",
        "maude_refs": [
            "maude/tls-data.maude:103-118",
            "maude/tls-data.maude:238-253",
            "maude/rfc-requirements.maude:636-684",
            "maude/rfc-requirements.maude:1452-1459",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0088": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_clienthello_legacy_sha1_signature_schemes_lowest_priority",
        "maude_refs": [
            "maude/rfc-requirements.maude:509-543",
            "maude/rfc-requirements.maude:935-938",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0091": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_deprecated_signature_algorithms_rejected_in_offers_requests_and_certificate_verify",
        "maude_refs": [
            "maude/rfc-requirements.maude:509-521",
            "maude/rfc-requirements.maude:584-587",
            "maude/rfc-requirements.maude:935-938",
            "maude/rfc-requirements.maude:1443-1446",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0092": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_md5_sha224_dsa_signature_algorithms_rejected",
        "maude_refs": [
            "maude/rfc-requirements.maude:509-521",
            "maude/rfc-requirements.maude:584-587",
            "maude/rfc-requirements.maude:935-938",
            "maude/rfc-requirements.maude:1443-1446",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0093": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_signature_curve_acceptance_reuses_supported_groups_abstraction",
        "maude_refs": [
            "maude/tls-data.maude:103-118",
            "maude/scenario/script/all-values.maude:53-68",
            "maude/rfc-requirements.maude:1668-1674",
            "maude/rfc-requirements.maude:1740-1743",
            "maude/rfc-requirements.maude:2067-2070",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0099": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_oid_filters_reject_duplicate_certificate_extension_oids",
        "maude_refs": [
            "maude/tls-data.maude:130-158",
            "maude/api/common-aux.maude:342-344",
            "maude/rfc-requirements.maude:552-576",
            "maude/rfc-requirements.maude:581-582",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0100": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_oid_filters_reject_any_extended_key_usage",
        "maude_refs": [
            "maude/tls-data.maude:130-158",
            "maude/rfc-requirements.maude:566-576",
            "maude/rfc-requirements.maude:581-582",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0004": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_application_data_not_sent_before_finished_except_early_data",
        "maude_refs": [
            "maude/tls-message.maude:34",
            "maude/api/connect-v3.maude:113-131",
            "maude/api/connect-v3.maude:383-401",
            "maude/api/accept-v3.maude:327-337",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0013": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_hrr_second_client_hello_checked_against_first_client_hello",
        "maude_refs": [
            "maude/api/accept-v3.maude:41-73",
            "maude/api/connect-v3.maude:98-111",
            "maude/rfc-requirements.maude:517-598",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0037": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_hrr_random_distinguishes_hello_retry_request_from_server_hello",
        "maude_refs": [
            "maude/api/accept-v3.maude:132-143",
            "maude/api/connect-v3.maude:153-173",
            "maude/api/connect-v3.maude:205-238",
            "maude/api/connect-v3.maude:719-724",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0136": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_accepted_early_data_decrypt_failure_terminates_with_bad_record_mac",
        "maude_refs": [
            "maude/api/accept-v3.maude:112-133",
            "maude/api/common-aux.maude:710-745",
            "maude/tls-data.maude:269",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0150": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_early_data_server_flight_sent_before_end_of_early_data",
        "maude_refs": [
            "maude/api/accept-v3.maude:41-79",
            "maude/api/accept-v3.maude:112-133",
            "maude/api/accept-v3.maude:223-231",
            "maude/api/accept-v3.maude:345-359",
            "maude/api/accept-v3.maude:374-387",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0155": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_request_context_unique_within_connection",
        "maude_refs": [
            "maude/api/accept-v3.maude:257-271",
            "maude/api/accept-v3.maude:551-563",
            "maude/api/connect-v3.maude:300-314",
            "maude/api/connect-v3.maude:582-599",
            "maude/rfc-requirements.maude:98-104",
            "maude/rfc-requirements.maude:1297-1313",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0160": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_certificate_only_after_certificate_request",
        "maude_refs": [
            "maude/api/connect-v3.maude:416-432",
            "maude/api/accept-v3.maude:404-439",
            "maude/api/accept-v3.maude:452-464",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0161": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_empty_client_certificate_allowed_when_no_suitable_certificate",
        "maude_refs": [
            "maude/api/connect-v3.maude:416-432",
            "maude/api/accept-v3.maude:431-439",
            "maude/rfc-requirements.maude:1349-1351",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0162": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_finished_sent_after_empty_or_absent_certificate",
        "maude_refs": [
            "maude/api/connect-v3.maude:416-491",
            "maude/api/accept-v3.maude:327-337",
            "maude/api/accept-v3.maude:355-453",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0165": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls_certificate_list_first_entry_used_as_sender_end_entity_certificate",
        "maude_refs": [
            "maude/api/common-aux.maude:697-700",
            "maude/rfc-requirements.maude:650-658",
            "maude/rfc-requirements.maude:681-684",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0166": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls_certificate_chain_order_allows_extra_certs_but_first_entry_remains_end_entity",
        "maude_refs": [
            "maude/api/common-aux.maude:697-700",
            "maude/rfc-requirements.maude:650-658",
            "maude/rfc-requirements.maude:681-684",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0168": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_openpgp_certificate_type_rejected",
        "maude_refs": [
            "maude/tls-data.maude:247-253",
            "maude/rfc-requirements.maude:611-614",
            "maude/rfc-requirements.maude:1373-1377",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0176": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_certificate_public_key_matches_selected_signature_authentication",
        "maude_refs": [
            "maude/rfc-requirements.maude:636-658",
            "maude/rfc-requirements.maude:1362-1365",
            "maude/api/connect-v3.maude:341-345",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0177": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_key_usage_digital_signature_required_if_present",
        "maude_refs": [
            "maude/tls-data.maude:160-168",
            "maude/tls-data.maude:243-244",
            "maude/rfc-requirements.maude:616-632",
            "maude/rfc-requirements.maude:650-658",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0178": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_signing_use_checked_against_advertised_signature_schemes",
        "maude_refs": [
            "maude/rfc-requirements.maude:616-632",
            "maude/rfc-requirements.maude:650-658",
            "maude/rfc-requirements.maude:681-684",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0179": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_chain_signature_algorithms_checked_against_client_advertisement",
        "maude_refs": [
            "maude/rfc-requirements.maude:650-658",
            "maude/rfc-requirements.maude:1362-1365",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0180": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_sha1_certificate_chain_rejected_unless_explicitly_modeled_as_legacy_clienthello_advertisement",
        "maude_refs": [
            "maude/rfc-requirements.maude:509-543",
            "maude/rfc-requirements.maude:604-609",
            "maude/rfc-requirements.maude:1373-1377",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0181": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_unacceptable_certificate_chain_uses_certificate_related_alert",
        "maude_refs": [
            "maude/rfc-requirements.maude:111-114",
            "maude/rfc-requirements.maude:1362-1377",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0186": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_md5_signature_aborts_with_bad_certificate",
        "maude_refs": [
            "maude/rfc-requirements.maude:110-113",
            "maude/rfc-requirements.maude:604-609",
            "maude/rfc-requirements.maude:1373-1377",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0190": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_certificate_verify_algorithm_must_be_client_offered",
        "maude_refs": [
            "maude/rfc-requirements.maude:1436-1441",
            "maude/api/connect-v3.maude:362-377",
            "maude/api/accept-v3.maude:321-332",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0191": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_certificate_verify_algorithm_must_be_certificate_request_offered",
        "maude_refs": [
            "maude/rfc-requirements.maude:1436-1441",
            "maude/api/accept-v3.maude:465-480",
            "maude/api/connect-v3.maude:492-502",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0192": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_verify_algorithm_compatible_with_sender_end_entity_certificate_key",
        "maude_refs": [
            "maude/rfc-requirements.maude:636-643",
            "maude/rfc-requirements.maude:681-684",
            "maude/rfc-requirements.maude:1414-1421",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0194": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_verify_rejects_sha1_signature_algorithm",
        "maude_refs": [
            "maude/rfc-requirements.maude:544-547",
            "maude/rfc-requirements.maude:1443-1446",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0200": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_sends_end_of_early_data_after_server_finished_when_early_data_selected",
        "maude_refs": [
            "maude/tls-data.maude:10-15",
            "maude/api/common-aux.maude:137-147",
            "maude/scenario/script/initialize.maude:185-192",
            "maude/api/accept-v3.maude:223-231",
            "maude/api/connect-v3.maude:387-406",
            "maude/api/connect-v3.maude:421-430",
            "maude/api/accept-v3.maude:374-387",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0201": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_omits_end_of_early_data_when_early_data_not_selected",
        "maude_refs": [
            "maude/api/common-aux.maude:137-147",
            "maude/api/common-aux.maude:339-341",
            "maude/api/accept-v3.maude:223-231",
            "maude/api/connect-v3.maude:404-406",
            "maude/api/connect-v3.maude:421-430",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0199": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_post_finished_records_use_application_traffic_keys",
        "maude_refs": [
            "maude/api/common-aux.maude:544-549",
            "maude/api/accept-v3.maude:345-359",
            "maude/api/connect-v3.maude:387-406",
            "maude/api/accept-v3.maude:527-535",
            "maude/api/accept-v3.maude:551-563",
            "maude/api/accept-v3.maude:578-588",
            "maude/api/connect-v3.maude:615-626",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0244": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_application_data_record_builders_never_write_unprotected_records",
        "maude_refs": [
            "maude/api/common-aux.maude:544-549",
            "maude/api/connect-v3.maude:126-132",
            "maude/api/accept-v3.maude:345-359",
            "maude/api/connect-v3.maude:522-531",
            "maude/api/accept-v3.maude:694-701",
            "maude/api/connect-v3.maude:720-727",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0247": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_decryption_failure_terminates_with_bad_record_mac",
        "maude_refs": [
            "maude/tls-data.maude:269",
            "maude/handshake-state.maude:27-29",
            "maude/handshake-state.maude:61-63",
            "maude/api/common-aux.maude:710-745",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0253": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_record_padding_is_zero_length_in_current_abstraction",
        "maude_refs": [
            "maude/api/common-aux.maude:544-549",
            "maude/crypto.maude:31",
            "maude/tls-message.maude:34",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0256": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_record_parser_only_sees_aead_decrypted_cleartext",
        "maude_refs": [
            "maude/api/common-aux.maude:703-708",
            "maude/api/common-aux.maude:710-745",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0266": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_closure_alert_enters_terminal_error_state",
        "maude_refs": [
            "maude/handshake-state.maude:27-29",
            "maude/handshake-state.maude:61-63",
            "maude/api/connect-v3.maude:672-680",
            "maude/api/accept-v3.maude:635-642",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0267": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_closure_alert_enters_terminal_error_state",
        "maude_refs": [
            "maude/handshake-state.maude:27-29",
            "maude/handshake-state.maude:61-63",
            "maude/api/connect-v3.maude:672-680",
            "maude/api/accept-v3.maude:635-642",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0268": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_close_notify_sent_before_write_close",
        "maude_refs": [
            "maude/tls-data.maude:225-239",
            "maude/handshake-state.maude:27-34",
            "maude/handshake-state.maude:61-68",
            "maude/api/connect-v3.maude:680-701",
            "maude/api/accept-v3.maude:641-661",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0273": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_ecdh_shared_secret_is_symbolic_and_not_truncated",
        "maude_refs": [
            "maude/tls-data.maude:63-65",
            "maude/api/common-aux.maude:575-579",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0017": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_hello_legacy_version_checked",
        "maude_refs": [
            "maude/api/accept-v3.maude:41-73",
            "maude/api/connect-v3.maude:36-52",
            "maude/api/connect-v3.maude:98-111",
            "maude/rfc-requirements.maude:659-672",
            "maude/scenario/rfc/psk.maude:772-779",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0025": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_ignores_unrecognized_clienthello_extensions",
        "maude_refs": [
            "maude/tls-data.maude:343-351",
            "maude/api/common-aux.maude:167-186",
            "maude/api/common-aux.maude:296-299",
            "maude/api/accept-v3.maude:41-73",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0035": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_serverhello_extension_allowlist_is_strict",
        "maude_refs": [
            "maude/rfc-requirements.maude:335-344",
            "maude/rfc-requirements.maude:919-925",
            "maude/api/common-aux.maude:300-305",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0036": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_serverhello_requires_supported_versions",
        "maude_refs": [
            "maude/api/common-aux.maude:302-303",
            "maude/api/accept-v3.maude:163-180",
            "maude/rfc-requirements.maude:891-893",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0055": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_extension_responses_require_peer_request_except_hrr_cookie",
        "maude_refs": [
            "maude/rfc-requirements.maude:298-314",
            "maude/rfc-requirements.maude:347-354",
            "maude/rfc-requirements.maude:397-415",
            "maude/rfc-requirements.maude:919-921",
            "maude/rfc-requirements.maude:954-961",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0056": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_unsolicited_extension_response_maps_to_unsupported_extension",
        "maude_refs": [
            "maude/rfc-requirements.maude:74",
            "maude/rfc-requirements.maude:93",
            "maude/rfc-requirements.maude:919-921",
            "maude/rfc-requirements.maude:954-961",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0059": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_duplicate_extension_blocks_rejected",
        "maude_refs": [
            "maude/api/common-aux.maude:335-354",
            "maude/rfc-requirements.maude:753-755",
            "maude/rfc-requirements.maude:806-808",
            "maude/rfc-requirements.maude:931-933",
            "maude/rfc-requirements.maude:1007-1009",
            "maude/rfc-requirements.maude:1268-1270",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0076": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_hrr_cookie_copied_into_second_clienthello",
        "maude_refs": [
            "maude/api/common-aux.maude:325-330",
            "maude/api/connect-v3.maude:98-111",
            "maude/api/connect-v3.maude:153-183",
            "maude/rfc-requirements.maude:554-600",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0077": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_initial_clienthello_builder_filters_cookie",
        "maude_refs": [
            "maude/api/common-aux.maude:274-299",
            "maude/api/connect-v3.maude:36-52",
            "maude/api/connect-v3.maude:98-111",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0095": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_oid_filters_only_allowed_in_certificate_request",
        "maude_refs": [
            "maude/tls-data.maude:348-349",
            "maude/api/common-aux.maude:321-322",
            "maude/rfc-requirements.maude:421-430",
            "maude/rfc-requirements.maude:1011-1013",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0102": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_filters_and_rejects_post_handshake_auth_extension",
        "maude_refs": [
            "maude/api/common-aux.maude:149-153",
            "maude/api/common-aux.maude:290-291",
            "maude/rfc-requirements.maude:335-344",
            "maude/rfc-requirements.maude:397-401",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0123": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_must_not_send_psk_key_exchange_modes",
        "maude_refs": [
            "maude/api/common-aux.maude:300-305",
            "maude/rfc-requirements.maude:335-344",
            "maude/rfc-requirements.maude:895-897",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0156": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_request_requires_signature_algorithms_and_allows_defined_extensions",
        "maude_refs": [
            "maude/api/common-aux.maude:319-322",
            "maude/rfc-requirements.maude:421-435",
            "maude/rfc-requirements.maude:1011-1013",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0157": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_request_unknown_extensions_ignored",
        "maude_refs": [
            "maude/tls-data.maude:346-347",
            "maude/rfc-requirements.maude:421-430",
            "maude/rfc-requirements.maude:1011-1013",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0171": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_status_request_v2_clienthello_ignored_and_not_sent_by_server",
        "maude_refs": [
            "maude/tls-data.maude:350-351",
            "maude/api/common-aux.maude:175-180",
            "maude/api/common-aux.maude:298-299",
            "maude/rfc-requirements.maude:397-435",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0172": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_status_request_v2_not_sent_in_encrypted_extensions_certificate_request_or_certificate",
        "maude_refs": [
            "maude/tls-data.maude:350-351",
            "maude/api/common-aux.maude:315-322",
            "maude/rfc-requirements.maude:397-435",
            "maude/rfc-requirements.maude:968-970",
            "maude/rfc-requirements.maude:1011-1013",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0173": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_clienthello_status_request_v2_is_parsed_and_ignored",
        "maude_refs": [
            "maude/tls-data.maude:350-351",
            "maude/api/common-aux.maude:175-180",
            "maude/api/common-aux.maude:298-299",
            "maude/api/accept-v3.maude:41-73",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0210": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_new_session_ticket_unknown_extensions_ignored",
        "maude_refs": [
            "maude/api/accept-v3.maude:527-536",
            "maude/api/connect-v3.maude:550-565",
            "maude/rfc-requirements.maude:436-442",
            "maude/rfc-requirements.maude:1248-1270",
            "maude/mbt/transform.maude:923-926",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0287": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_mandatory_extensions_modeled_for_applicable_features",
        "maude_refs": [
            "maude/rfc-requirements.maude:710-719",
            "maude/api/common-aux.maude:274-322",
            "maude/api/connect-v3.maude:36-52",
            "maude/api/accept-v3.maude:41-73",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0297": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_certificate_request_and_new_session_ticket_ignore_unknown_extensions",
        "maude_refs": [
            "maude/rfc-requirements.maude:421-442",
            "maude/rfc-requirements.maude:1011-1013",
            "maude/rfc-requirements.maude:1248-1270",
            "maude/api/connect-v3.maude:294-306",
            "maude/api/connect-v3.maude:550-565",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0323": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_truncated_hmac_extension_not_representable_or_generated",
        "maude_refs": [
            "maude/tls-data.maude:305-351",
            "maude/api/common-aux.maude:274-322",
            "maude/rfc-requirements.maude:335-442",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0031": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_random_generated_from_server_nonce_counter",
        "maude_refs": [
            "maude/api/accept-v3.maude:239-260",
            "maude/rfc-requirements.maude:1012-1019",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0033": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_rejects_unoffered_serverhello_cipher_suite",
        "maude_refs": [
            "maude/api/connect-v3.maude:205-278",
            "maude/rfc-requirements.maude:1078-1079",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0050": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_rejects_unoffered_hrr_cipher_suite",
        "maude_refs": [
            "maude/api/connect-v3.maude:153-187",
            "maude/rfc-requirements.maude:966-967",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0051": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_second_clienthello_invariants_preserve_cipher_suite_negotiation",
        "maude_refs": [
            "maude/api/accept-v3.maude:41-115",
            "maude/rfc-requirements.maude:865-878",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0052": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_serverhello_cipher_suite_must_match_hrr",
        "maude_refs": [
            "maude/api/connect-v3.maude:272-278",
            "maude/rfc-requirements.maude:1094-1102",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0053": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_serverhello_selected_version_must_match_hrr",
        "maude_refs": [
            "maude/api/connect-v3.maude:272-278",
            "maude/rfc-requirements.maude:1106-1114",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0054": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_serverhello_selected_version_change_alerts_illegal_parameter",
        "maude_refs": [
            "maude/api/connect-v3.maude:272-278",
            "maude/rfc-requirements.maude:61-62",
            "maude/rfc-requirements.maude:1106-1114",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0063": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_uses_supported_versions_not_clienthello_legacy_version",
        "maude_refs": [
            "maude/api/accept-v3.maude:41-115",
            "maude/rfc-requirements.maude:821-827",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0064": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_version_selection_ignores_clienthello_legacy_version",
        "maude_refs": [
            "maude/api/accept-v3.maude:41-115",
            "maude/rfc-requirements.maude:821-827",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0065": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_server_or_hrr_selected_version_must_be_client_offered",
        "maude_refs": [
            "maude/rfc-requirements.maude:950-951",
            "maude/rfc-requirements.maude:1118-1126",
            "maude/scenario/rfc/8446-core.maude:737-744",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0066": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_unknown_supported_versions_are_ignored_by_intersection_selection",
        "maude_refs": [
            "maude/tls-data.maude:26",
            "maude/api/common-aux.maude:61-63",
            "maude/rfc-requirements.maude:821-827",
            "maude/rfc-requirements.maude:1118-1126",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0103": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_supported_groups_in_encrypted_extensions_not_used_before_handshake_completion",
        "maude_refs": [
            "maude/api/connect-v3.maude:294-316",
            "maude/rfc-requirements.maude:470-478",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0304": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_obsolete_reserved_groups_rejected_by_named_group_allowlist",
        "maude_refs": [
            "maude/rfc-requirements.maude:269-288",
            "maude/rfc-requirements.maude:451-459",
            "maude/rfc-requirements.maude:904-910",
            "maude/rfc-requirements.maude:983-989",
            "maude/rfc-requirements.maude:1045-1054",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0307": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_client_rejects_unsupported_server_selected_version_with_protocol_version",
        "maude_refs": [
            "maude/rfc-requirements.maude:59-62",
            "maude/rfc-requirements.maude:1118-1126",
            "maude/scenario/rfc/8446-core.maude:737-744",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0310": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_missing_supported_versions_aborts_with_protocol_version",
        "maude_refs": [
            "maude/rfc-requirements.maude:42",
            "maude/rfc-requirements.maude:821-827",
            "maude/scenario/rfc/8446-core.maude:722-730",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0311": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_serverhello_legacy_version_is_not_used_for_negotiation",
        "maude_refs": [
            "maude/api/connect-v3.maude:205-278",
            "maude/rfc-requirements.maude:1090-1091",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0314": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_all_tls_rc4_cipher_suites_rejected_by_security_allowlist",
        "maude_refs": [
            "maude/rfc-requirements.maude:247-267",
            "maude/rfc-requirements.maude:892-893",
            "maude/rfc-requirements.maude:966-967",
            "maude/rfc-requirements.maude:1078-1079",
            "maude/rfc-requirements.maude:1878-1880",
            "maude/rfc-requirements.maude:1951-1952",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0315": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_all_tls_null_cipher_suites_rejected_by_security_allowlist",
        "maude_refs": [
            "maude/rfc-requirements.maude:247-267",
            "maude/rfc-requirements.maude:892-893",
            "maude/rfc-requirements.maude:966-967",
            "maude/rfc-requirements.maude:1078-1079",
            "maude/rfc-requirements.maude:1878-1880",
            "maude/rfc-requirements.maude:1951-1952",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0316": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_ssl30_not_negotiated_by_tls13_version_checks",
        "maude_refs": [
            "maude/tls-data.maude:26",
            "maude/rfc-requirements.maude:821-827",
            "maude/rfc-requirements.maude:1090-1091",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0317": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_ssl20_not_representable_or_negotiated",
        "maude_refs": [
            "maude/tls-data.maude:25-27",
            "maude/tls-message.maude:24-42",
            "maude/rfc-requirements.maude:821-827",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0318": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_ssl20_compatible_clienthello_not_representable_or_generated",
        "maude_refs": [
            "maude/tls-data.maude:10-15",
            "maude/api/connect-v3.maude:36-52",
            "maude/api/connect-v3.maude:98-111",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0319": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_cannot_be_negotiated_using_ssl20_compatible_clienthello",
        "maude_refs": [
            "maude/tls-data.maude:10-15",
            "maude/api/connect-v3.maude:36-52",
            "maude/api/accept-v3.maude:41-115",
            "maude/rfc-requirements.maude:821-827",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0320": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_hello_builders_send_tls12_legacy_version",
        "maude_refs": [
            "maude/api/connect-v3.maude:48",
            "maude/api/connect-v3.maude:107",
            "maude/api/accept-v3.maude:218",
            "maude/api/accept-v3.maude:253",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0321": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_ssl30_hello_version_aborts_with_protocol_version",
        "maude_refs": [
            "maude/tls-data.maude:26",
            "maude/scenario/script/all-values.maude:99-100",
            "maude/rfc-requirements.maude:821-827",
            "maude/rfc-requirements.maude:1090-1091",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0322": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_record_builders_send_tls12_record_version",
        "maude_refs": [
            "maude/api/common-aux.maude:524-544",
            "maude/api/common-aux.maude:547",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0009": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_record_content_type_checked",
        "maude_refs": [
            "maude/tls-data.maude:1-3",
            "maude/api/common-aux.maude:417-432",
            "maude/rfc-requirements.maude:1450-1458",
            "maude/rfc-requirements.maude:1515-1523",
            "maude/rfc-requirements.maude:1574-1592",
            "maude/rfc-requirements.maude:1648-1656",
            "maude/rfc-requirements.maude:1681-1689",
            "maude/rfc-requirements.maude:1724-1732",
            "maude/rfc-requirements.maude:1774-1780",
            "maude/rfc-requirements.maude:1792-1803",
            "maude/rfc-requirements.maude:1814-1820",
            "maude/rfc-requirements.maude:1836-1844",
            "maude/rfc-requirements.maude:1875-1917",
            "maude/scenario/rfc/5246-core.maude:59-66",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0010": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_unexpected_record_type_alert",
        "maude_refs": [
            "maude/rfc-requirements.maude:149-214",
            "maude/rfc-requirements.maude:238-246",
            "maude/rfc-requirements.maude:1450-1458",
            "maude/rfc-requirements.maude:1515-1523",
            "maude/rfc-requirements.maude:1574-1592",
            "maude/rfc-requirements.maude:1648-1656",
            "maude/rfc-requirements.maude:1681-1689",
            "maude/rfc-requirements.maude:1724-1732",
            "maude/rfc-requirements.maude:1774-1780",
            "maude/rfc-requirements.maude:1792-1803",
            "maude/rfc-requirements.maude:1814-1820",
            "maude/rfc-requirements.maude:1836-1844",
            "maude/rfc-requirements.maude:1875-1917",
            "maude/api/accept-v2.maude:529-538",
            "maude/scenario/rfc/5246-core.maude:59-66",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0008": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_cipher_suites_define_prf_selector",
        "maude_refs": [
            "maude/ciphersuite.maude:239-245",
            "maude/ciphersuite.maude:621-711",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0014": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_record_length_abstract_bounds_checked",
        "maude_refs": [
            "maude/tls-message.maude:24-28",
            "maude/api/common-aux.maude:529-550",
            "maude/rfc-requirements.maude:1511-1512",
            "maude/rfc-requirements.maude:1592-1593",
            "maude/rfc-requirements.maude:1657-1661",
            "maude/rfc-requirements.maude:1721-1722",
            "maude/rfc-requirements.maude:1754-1755",
            "maude/rfc-requirements.maude:1797-1798",
            "maude/rfc-requirements.maude:1842-1843",
            "maude/rfc-requirements.maude:1865-1866",
            "maude/rfc-requirements.maude:1882-1883",
            "maude/rfc-requirements.maude:1909-1910",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0015": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_zero_length_handshake_alert_ccs_rejected_by_length_checks",
        "maude_refs": [
            "maude/api/common-aux.maude:529-550",
            "maude/rfc-requirements.maude:1511-1512",
            "maude/rfc-requirements.maude:1592-1593",
            "maude/rfc-requirements.maude:1657-1661",
            "maude/rfc-requirements.maude:1721-1722",
            "maude/rfc-requirements.maude:1754-1755",
            "maude/rfc-requirements.maude:1797-1798",
            "maude/rfc-requirements.maude:1842-1843",
            "maude/rfc-requirements.maude:1865-1866",
            "maude/rfc-requirements.maude:1882-1883",
            "maude/rfc-requirements.maude:1909-1910",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0016": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_record_delivery_order_preserved_by_msg_queue",
        "maude_refs": [
            "maude/communication.maude:1-8",
            "maude/api/connect-v2.maude:24-30",
            "maude/api/accept-v2.maude:86-92",
            "maude/api/connect-v2.maude:521-528",
            "maude/api/accept-v2.maude:584-593",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0029": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_decrypt_failure_generates_fatal_bad_record_mac",
        "maude_refs": [
            "maude/api/common-aux.maude:625-634",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0032": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_fatal_failure_invalidates_session_identifier",
        "maude_refs": [
            "maude/component.maude:141-144",
            "maude/api/accept-v2.maude:537-556",
            "maude/api/accept-v2.maude:581-609",
            "maude/api/connect-v2.maude:474-493",
            "maude/api/connect-v2.maude:517-544",
            "maude/api/common-aux.maude:429-438",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0033": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_close_notify_reply_and_close",
        "maude_refs": [
            "maude/tls-data.maude:225-239",
            "maude/handshake-state.maude:13-17",
            "maude/handshake-state.maude:48-51",
            "maude/api/connect-v2.maude:474-490",
            "maude/api/accept-v2.maude:536-552",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0034": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_fatal_alert_clears_connection_session_keys_and_secrets",
        "maude_refs": [
            "maude/component.maude:141-144",
            "maude/api/accept-v2.maude:537-556",
            "maude/api/accept-v2.maude:581-609",
            "maude/api/connect-v2.maude:474-493",
            "maude/api/connect-v2.maude:517-544",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0035": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_fatal_alert_session_not_resumable",
        "maude_refs": [
            "maude/component.maude:141-144",
            "maude/api/common-aux.maude:429-438",
            "maude/api/common-aux.maude:440-445",
            "maude/api/accept-v2.maude:537-556",
            "maude/api/connect-v2.maude:474-493",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0036": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_fatal_condition_sends_alert_before_error_close",
        "maude_refs": [
            "maude/rfc-requirements.maude:31-216",
            "maude/rfc-requirements.maude:240-246",
            "maude/api/connect-v2.maude:521-535",
            "maude/api/accept-v2.maude:584-600",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0037": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_immediate_close_alerts_are_fatal",
        "maude_refs": [
            "maude/api/connect-v2.maude:521-535",
            "maude/api/accept-v2.maude:584-600",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0039": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_reserved_alert_description_not_sent",
        "maude_refs": [
            "maude/tls-data.maude:228-248",
            "maude/api/connect-v2.maude:521-535",
            "maude/api/accept-v2.maude:584-600",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0040": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_reserved_alert_description_not_sent",
        "maude_refs": [
            "maude/tls-data.maude:228-248",
            "maude/api/connect-v2.maude:521-535",
            "maude/api/accept-v2.maude:584-600",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0041": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_reserved_alert_description_not_sent",
        "maude_refs": [
            "maude/tls-data.maude:228-248",
            "maude/api/connect-v2.maude:521-535",
            "maude/api/accept-v2.maude:584-600",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0044": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_application_data_rejected_by_content_type_checks",
        "maude_refs": [
            "maude/api/common-aux.maude:417-432",
            "maude/rfc-requirements.maude:1450-1453",
            "maude/rfc-requirements.maude:1515-1518",
            "maude/rfc-requirements.maude:1574-1582",
            "maude/rfc-requirements.maude:1648-1651",
            "maude/rfc-requirements.maude:1681-1684",
            "maude/rfc-requirements.maude:1724-1727",
            "maude/rfc-requirements.maude:1774-1777",
            "maude/rfc-requirements.maude:1797-1800",
            "maude/rfc-requirements.maude:1836-1839",
            "maude/rfc-requirements.maude:1875-1917",
            "maude/scenario/rfc/5246-core.maude:59-66",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0046": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_handshake_order_state_machine",
        "maude_refs": [
            "maude/handshake-state.maude:13-16",
            "maude/handshake-state.maude:48-51",
            "maude/rfc-requirements.maude:138-214",
            "maude/rfc-requirements.maude:238-246",
            "maude/rfc-requirements.maude:1450-1854",
            "maude/rfc-requirements.maude:1875-1917",
            "maude/api/accept-v2.maude:529-548",
            "maude/api/connect-v2.maude:496-514",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0049": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_unsupported_cipher_suites_ignored_by_selection",
        "maude_refs": [
            "maude/api/common-aux.maude:64-85",
            "maude/api/accept-v2.maude:48-53",
            "maude/rfc-requirements.maude:1497-1500",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0050": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_resumption_clienthello_includes_session_cipher_suite",
        "maude_refs": [
            "maude/rfc-requirements.maude:1479-1483",
            "maude/rfc-requirements.maude:1496-1499",
            "maude/rfc-requirements.maude:1943-1952",
            "maude/rfc-requirements.maude:1996-2005",
            "maude/api/accept-v2.maude:51-68",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0051": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_resumption_clienthello_includes_session_compression_method",
        "maude_refs": [
            "maude/rfc-requirements.maude:1485-1489",
            "maude/rfc-requirements.maude:1501-1504",
            "maude/rfc-requirements.maude:1943-1952",
            "maude/rfc-requirements.maude:1996-2005",
            "maude/api/accept-v2.maude:51-68",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0054": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_client_hello_extension_format_and_decode_error",
        "maude_refs": [
            "maude/api/accept-v2.maude:48-63",
            "maude/api/common-aux.maude:499-520",
            "maude/rfc-requirements.maude:138-150",
            "maude/rfc-requirements.maude:1450-1461",
            "maude/scenario/rfc/5246-core.maude:59-66",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0057": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_server_random_generated_independently_from_server_nonce_counter",
        "maude_refs": [
            "maude/api/accept-v2.maude:86-101",
            "maude/api/connect-v2.maude:24-32",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0059": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_server_hello_extension_must_be_requested",
        "maude_refs": [
            "maude/api/common-aux.maude:228-248",
            "maude/api/common-aux.maude:324-326",
            "maude/api/connect-v2.maude:81-94",
            "maude/rfc-requirements.maude:1324-1337",
            "maude/rfc-requirements.maude:1524-1536",
            "maude/scenario/rfc/5246-core.maude:491-496",
            "maude/scenario/rfc/5246-core.maude:544-569",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0060": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_unsolicited_server_hello_extension_unsupported_extension_alert",
        "maude_refs": [
            "maude/api/common-aux.maude:228-248",
            "maude/api/common-aux.maude:324-326",
            "maude/api/connect-v2.maude:81-94",
            "maude/rfc-requirements.maude:152-162",
            "maude/rfc-requirements.maude:1324-1337",
            "maude/rfc-requirements.maude:1524-1536",
            "maude/scenario/rfc/5246-core.maude:491-496",
            "maude/scenario/rfc/5246-core.maude:544-569",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0066": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_server_must_not_send_signature_algorithms",
        "maude_refs": [
            "maude/api/accept-v2.maude:94-97",
            "maude/api/common-aux.maude:325-330",
            "maude/api/connect-v2.maude:82-92",
            "maude/rfc-requirements.maude:1331-1333",
            "maude/rfc-requirements.maude:1538-1539",
            "maude/scenario/rfc/5246-core.maude:520-540",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0067": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_server_supports_receiving_signature_algorithms",
        "maude_refs": [
            "maude/tls-data.maude:296-298",
            "maude/api/accept-v2.maude:48-63",
            "maude/api/common-aux.maude:228-232",
            "maude/rfc-requirements.maude:1287-1294",
            "maude/rfc-requirements.maude:1297-1308",
            "maude/rfc-requirements.maude:1467-1479",
            "maude/scenario/script/initialize.maude:147-148",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0004": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_empty_client_certificate_list_built_when_no_suitable_certificate",
        "maude_refs": [
            "maude/api/connect-v2.maude:198-205",
            "maude/api/connect-v2.maude:252-274",
            "maude/scenario/script/normal-behavior-v2.maude:7-10",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0043": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_certificate_request_forces_client_certificate_message",
        "maude_refs": [
            "maude/api/connect-v2.maude:198-205",
            "maude/api/connect-v2.maude:247-266",
            "maude/api/connect-v2.maude:299-306",
            "maude/scenario/script/normal-behavior-v2.maude:7-10",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0069": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_server_certificate_matches_negotiated_cipher_suite_and_extensions",
        "maude_refs": [
            "maude/api/accept-v2.maude:122-134",
            "maude/api/connect-v2.maude:117-128",
            "maude/rfc-requirements.maude:1370-1381",
            "maude/rfc-requirements.maude:1636-1662",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0073": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_end_entity_public_key_matches_selected_key_exchange_model",
        "maude_refs": [
            "maude/api/connect-v2.maude:117-128",
            "maude/rfc-requirements.maude:1351-1358",
            "maude/rfc-requirements.maude:1370-1381",
            "maude/rfc-requirements.maude:1660-1662",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0085": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_server_key_exchange_signature_algorithm_offered",
        "maude_refs": [
            "maude/api/accept-v2.maude:177-215",
            "maude/api/connect-v2.maude:154-170",
            "maude/rfc-requirements.maude:1432-1437",
            "maude/rfc-requirements.maude:1769-1774",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0086": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_cipher_suite_candidates_filtered_by_signature_algorithms",
        "maude_refs": [
            "maude/api/common-aux.maude:68-85",
            "maude/api/accept-v2.maude:48-53",
            "maude/rfc-requirements.maude:1497-1500",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0087": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_server_key_exchange_signature_algorithm_matches_server_certificate",
        "maude_refs": [
            "maude/api/accept-v2.maude:177-210",
            "maude/api/connect-v2.maude:155-173",
            "maude/rfc-requirements.maude:1425-1428",
            "maude/rfc-requirements.maude:1780-1783",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0092": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_client_certificate_matches_negotiated_cipher_suite_and_requested_extensions",
        "maude_refs": [
            "maude/api/connect-v2.maude:255-274",
            "maude/api/accept-v2.maude:304-315",
            "maude/rfc-requirements.maude:1370-1381",
            "maude/rfc-requirements.maude:1640-1666",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0106": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_rsa_pms_uses_selected_clienthello_version",
        "maude_refs": [
            "maude/api/connect-v2.maude:302-320",
            "maude/api/accept-v2.maude:346-360",
            "maude/api/accept-v2.maude:367-372",
            "maude/api/accept-v2.maude:382-387",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0107": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_rsa_pms_version_checked_with_random_fallback",
        "maude_refs": [
            "maude/api/accept-v2.maude:346-360",
            "maude/api/accept-v2.maude:367-387",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0108": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_rsa_pms_processing_failure_does_not_alert",
        "maude_refs": [
            "maude/api/accept-v2.maude:353-358",
            "maude/api/accept-v2.maude:365-382",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0109": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_rsa_pms_processing_failure_uses_random_premaster_secret",
        "maude_refs": [
            "maude/api/accept-v2.maude:362-367",
            "maude/api/accept-v2.maude:377-382",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0113": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_certificate_verify_immediately_after_cke",
        "maude_refs": [
            "maude/api/connect-v2.maude:297-319",
            "maude/api/connect-v2.maude:339-355",
            "maude/api/accept-v2.maude:326-350",
            "maude/api/accept-v2.maude:372-388",
            "maude/rfc-requirements.maude:1681-1692",
            "maude/rfc-requirements.maude:1903-1910",
        ],
        "old_row_ids": [],
    },
    "5246-MUST-0114": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_certificate_verify_algorithm_was_requested",
        "maude_refs": [
            "maude/api/connect-v2.maude:353-362",
            "maude/api/accept-v2.maude:409-423",
            "maude/rfc-requirements.maude:1724-1730",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0115": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_certificate_verify_algorithm_matches_client_certificate_key",
        "maude_refs": [
            "maude/api/connect-v2.maude:353-362",
            "maude/api/accept-v2.maude:409-423",
            "maude/rfc-requirements.maude:1425-1428",
            "maude/rfc-requirements.maude:1706-1709",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0116": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_finished_verify_data_checked_against_transcript_and_master_secret",
        "maude_refs": [
            "maude/api/accept-v2.maude:452-465",
            "maude/api/connect-v2.maude:442-455",
            "maude/rfc-requirements.maude:1449-1450",
            "maude/rfc-requirements.maude:1879-1884",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0117": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_finished_hash_uses_cipher_suite_prf_hash_basis",
        "maude_refs": [
            "maude/api/accept-v2.maude:505-516",
            "maude/api/connect-v2.maude:392-402",
            "maude/api/accept-v2.maude:452-465",
            "maude/api/connect-v2.maude:442-455",
            "maude/rfc-requirements.maude:1879-1884",
            "maude/ciphersuite.maude:238",
            "maude/ciphersuite.maude:613-703",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0118": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_modeled_cipher_suites_define_finished_hash_selector",
        "maude_refs": [
            "maude/ciphersuite.maude:238",
            "maude/ciphersuite.maude:613-703",
            "maude/api/accept-v2.maude:505-516",
            "maude/api/connect-v2.maude:392-402",
            "maude/rfc-requirements.maude:1879-1884",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0119": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_finished_verify_data_length_minimum_metadata",
        "maude_refs": [
            "maude/ciphersuite.maude:240-245",
            "maude/api/accept-v2.maude:508-520",
            "maude/api/connect-v2.maude:394-404",
            "maude/rfc-requirements.maude:1886-1918",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "5246-MUST-0120": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls12_mandatory_cipher_suite_supported_by_model",
        "maude_refs": [
            "maude/ciphersuite.maude:140",
            "maude/ciphersuite.maude:247",
            "maude/ciphersuite.maude:338",
            "maude/ciphersuite.maude:428",
            "maude/ciphersuite.maude:523",
            "maude/ciphersuite.maude:618",
            "maude/scenario/script/all-values.maude:70-73",
        ],
        "replace_maude_refs": True,
        "old_row_ids": [],
    },
    "8446-MUST-0223": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_ccs_content_type_handled_by_state_checks",
        "maude_refs": [
            "maude/tls-data.maude:1-3",
            "maude/tls-message.maude:24-37",
            "maude/rfc-requirements.maude:47-128",
            "maude/rfc-requirements.maude:588-593",
            "maude/rfc-requirements.maude:752-757",
            "maude/rfc-requirements.maude:832-837",
            "maude/rfc-requirements.maude:922-925",
            "maude/rfc-requirements.maude:959-962",
            "maude/rfc-requirements.maude:1003-1011",
            "maude/rfc-requirements.maude:1085-1088",
            "maude/rfc-requirements.maude:1139-1142",
            "maude/rfc-requirements.maude:1211-1255",
            "maude/api/accept-v3.maude:662-679",
            "maude/api/connect-v3.maude:702-724",
        ],
        "old_row_ids": [],
    },
    "8446-MUST-0224": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_ccs_unexpected_content_type_rejected",
        "maude_refs": [
            "maude/tls-data.maude:1-3",
            "maude/tls-message.maude:24-37",
            "maude/rfc-requirements.maude:47-128",
            "maude/rfc-requirements.maude:238-246",
            "maude/rfc-requirements.maude:588-593",
            "maude/rfc-requirements.maude:752-757",
            "maude/rfc-requirements.maude:832-837",
            "maude/rfc-requirements.maude:922-925",
            "maude/rfc-requirements.maude:959-962",
            "maude/rfc-requirements.maude:1003-1011",
            "maude/rfc-requirements.maude:1085-1088",
            "maude/rfc-requirements.maude:1139-1142",
            "maude/rfc-requirements.maude:1211-1255",
            "maude/api/accept-v3.maude:662-679",
            "maude/api/connect-v3.maude:702-724",
        ],
        "old_row_ids": [],
    },
    "8446-MUST-0225": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_ccs_treated_as_unexpected_record_type",
        "maude_refs": [
            "maude/tls-data.maude:1-3",
            "maude/tls-message.maude:24-37",
            "maude/rfc-requirements.maude:47-128",
            "maude/rfc-requirements.maude:238-246",
            "maude/rfc-requirements.maude:588-593",
            "maude/rfc-requirements.maude:752-757",
            "maude/rfc-requirements.maude:832-837",
            "maude/rfc-requirements.maude:922-925",
            "maude/rfc-requirements.maude:959-962",
            "maude/rfc-requirements.maude:1003-1011",
            "maude/rfc-requirements.maude:1085-1088",
            "maude/rfc-requirements.maude:1139-1142",
            "maude/rfc-requirements.maude:1211-1255",
            "maude/api/accept-v3.maude:662-679",
            "maude/api/connect-v3.maude:702-724",
        ],
        "old_row_ids": [],
    },
    "8446-MUST-0259": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_error_alert_enters_connection_close_state",
        "maude_refs": [
            "maude/handshake-state.maude:27-29",
            "maude/handshake-state.maude:61-63",
            "maude/api/connect-v3.maude:672-677",
            "maude/api/accept-v3.maude:635-640",
        ],
        "old_row_ids": [],
    },
    "8446-MUST-0270": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_fatal_alert_send_or_receive_closes_connection",
        "maude_refs": [
            "maude/handshake-state.maude:27-29",
            "maude/handshake-state.maude:61-63",
            "maude/api/connect-v3.maude:672-677",
            "maude/api/connect-v3.maude:702-724",
            "maude/api/accept-v3.maude:635-640",
            "maude/api/accept-v3.maude:662-679",
        ],
        "old_row_ids": [],
    },
    "8446-MUST-0271": {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": "manual_audit_tls13_fatal_error_sends_alert_and_enters_close_state",
        "maude_refs": [
            "maude/handshake-state.maude:27-29",
            "maude/handshake-state.maude:61-63",
            "maude/rfc-requirements.maude:31-136",
            "maude/rfc-requirements.maude:238-246",
            "maude/rfc-requirements.maude:1211-1255",
            "maude/api/connect-v3.maude:702-724",
            "maude/api/accept-v3.maude:662-679",
        ],
        "old_row_ids": [],
    },
}


def _manual_implemented(reason_code: str, maude_refs: list[str]) -> dict[str, object]:
    return {
        "status": "Implemented",
        "coverage": "covered",
        "scope": "in_scope_manual_audit",
        "reason_code": reason_code,
        "maude_refs": maude_refs,
        "replace_maude_refs": True,
        "old_row_ids": [],
    }


_TLS13_BATCH_OVERRIDES = {
    "8446-MUST-0006": _manual_implemented(
        "manual_audit_tls13_psk_identity_and_kdf_hash_carried_by_pskinfo",
        [
            "maude/component.maude:70-71",
            "maude/component.maude:187",
            "maude/api/common-aux.maude:246-248",
            "maude/api/connect-v3.maude:57-59",
        ],
    ),
    "8446-MUST-0010": _manual_implemented(
        "manual_audit_tls13_psk_selection_requires_client_server_mode_overlap",
        [
            "maude/api/accept-v3.maude:41-73",
            "maude/rfc-requirements.maude:504-532",
            "maude/rfc-requirements.maude:967-990",
        ],
    ),
    "8446-MUST-0014": _manual_implemented(
        "manual_audit_tls13_established_connection_clienthello_aborts_unexpected_message",
        [
            "maude/api/accept-v3.maude:753-801",
            "maude/rfc-requirements.maude:924-934",
            "maude/rfc-requirements.maude:1738-1779",
        ],
    ),
    "8446-MUST-0015": _manual_implemented(
        "manual_audit_tls12_renegotiation_tls13_clienthello_retains_previous_tls12_version",
        [
            "maude/api/accept-v2.maude:37-67",
            "maude/rfc-requirements.maude:1731-1749",
            "maude/rfc-requirements.maude:2029-2037",
        ],
    ),
    "8446-MUST-0016": _manual_implemented(
        "manual_audit_tls12_renegotiation_tls13_clienthello_does_not_negotiate_tls13",
        [
            "maude/api/accept-v2.maude:37-67",
            "maude/rfc-requirements.maude:1731-1749",
            "maude/rfc-requirements.maude:2029-2037",
            "maude/rfc-requirements.maude:2164",
        ],
    ),
    "8446-MUST-0018": _manual_implemented(
        "manual_audit_tls13_clienthello_legacy_session_id_generated_nonempty",
        [
            "maude/api/connect-v3.maude:36-52",
            "maude/tls-data.maude:262-270",
        ],
    ),
    "8446-MUST-0019": _manual_implemented(
        "manual_audit_tls13_clienthello_legacy_session_id_generated_nonempty",
        [
            "maude/api/connect-v3.maude:36-52",
            "maude/tls-data.maude:262-270",
        ],
    ),
    "8446-MUST-0032": _manual_implemented(
        "manual_audit_tls13_client_rejects_serverhello_session_id_echo_mismatch",
        [
            "maude/api/connect-v3.maude:205-241",
            "maude/rfc-requirements.maude:1171-1173",
            "maude/rfc-requirements.maude:1790-1794",
        ],
    ),
    "8446-MUST-0043": _manual_implemented(
        "manual_audit_tls12_renegotiation_client_rejects_tls13_serverhello_protocol_version",
        [
            "maude/api/connect-v2.maude:69-96",
            "maude/api/connect-v2.maude:521-535",
            "maude/rfc-requirements.maude:2193-2202",
            "maude/rfc-requirements.maude:2420-2425",
        ],
    ),
    "8446-MUST-0101": _manual_implemented(
        "manual_audit_tls13_server_sends_post_handshake_certificate_request_only_if_client_offered_extension",
        [
            "maude/api/accept-v3.maude:593-606",
            "maude/rfc-requirements.maude:790-792",
        ],
    ),
    "8446-MUST-0120": _manual_implemented(
        "manual_audit_tls13_clienthello_psk_requires_psk_key_exchange_modes",
        [
            "maude/rfc-requirements.maude:999-1001",
        ],
    ),
    "8446-MUST-0121": _manual_implemented(
        "manual_audit_tls13_server_aborts_psk_without_psk_key_exchange_modes",
        [
            "maude/api/accept-v3.maude:41-73",
            "maude/rfc-requirements.maude:999-1001",
        ],
    ),
    "8446-MUST-0122": _manual_implemented(
        "manual_audit_tls13_server_psk_mode_selection_requires_client_server_mode_overlap",
        [
            "maude/rfc-requirements.maude:504-532",
            "maude/rfc-requirements.maude:967-990",
            "maude/rfc-requirements.maude:1175-1177",
            "maude/rfc-requirements.maude:1155-1157",
        ],
    ),
    "8446-MUST-0124": _manual_implemented(
        "manual_audit_tls13_psk_ke_serverhello_must_not_include_key_share",
        [
            "maude/rfc-requirements.maude:478-482",
            "maude/rfc-requirements.maude:1289-1291",
        ],
    ),
    "8446-MUST-0125": _manual_implemented(
        "manual_audit_tls13_psk_dhe_requires_client_and_server_key_share",
        [
            "maude/rfc-requirements.maude:485-492",
            "maude/rfc-requirements.maude:992-1006",
            "maude/rfc-requirements.maude:1269-1271",
        ],
    ),
    "8446-MUST-0129": _manual_implemented(
        "manual_audit_tls13_early_data_accept_reject_discard_paths_modeled",
        [
            "maude/api/accept-v3.maude:98-160",
            "maude/api/connect-v3.maude:114-132",
            "maude/rfc-requirements.maude:992-997",
        ],
    ),
    "8446-MUST-0131": _manual_implemented(
        "manual_audit_tls13_early_data_acceptance_requires_first_selected_psk",
        [
            "maude/api/accept-v3.maude:89-95",
            "maude/api/accept-v3.maude:116-147",
            "maude/rfc-requirements.maude:543-548",
        ],
    ),
    "8446-MUST-0132": _manual_implemented(
        "manual_audit_tls13_selected_psk_hash_matches_selected_cipher_suite",
        [
            "maude/rfc-requirements.maude:535-564",
            "maude/rfc-requirements.maude:1260-1264",
            "maude/api/connect-v3.maude:207-263",
        ],
    ),
    "8446-MUST-0138": _manual_implemented(
        "manual_audit_tls13_external_psk_obfuscated_ticket_age_not_modeled_or_used",
        [
            "maude/tls-message.maude:80",
            "maude/component.maude:70-71",
            "maude/api/accept-v3.maude:89-95",
        ],
    ),
    "8446-MUST-0139": _manual_implemented(
        "manual_audit_tls13_external_psk_hash_set_by_pskinfo_cipher_suite",
        [
            "maude/component.maude:70-71",
            "maude/api/common-aux.maude:246-248",
            "maude/api/connect-v3.maude:57-59",
        ],
    ),
    "8446-MUST-0140": _manual_implemented(
        "manual_audit_tls13_server_selects_psk_compatible_with_cipher_suite_hash",
        [
            "maude/api/connect-v3.maude:207-263",
            "maude/rfc-requirements.maude:535-564",
            "maude/rfc-requirements.maude:1260-1264",
        ],
    ),
    "8446-MUST-0143": _manual_implemented(
        "manual_audit_tls13_client_checks_selected_identity_range_hash_and_key_share_consistency",
        [
            "maude/api/connect-v3.maude:207-263",
            "maude/rfc-requirements.maude:478-503",
            "maude/rfc-requirements.maude:1260-1271",
        ],
    ),
    "8446-MUST-0144": _manual_implemented(
        "manual_audit_tls13_client_aborts_inconsistent_selected_psk_parameters",
        [
            "maude/api/connect-v3.maude:207-263",
            "maude/rfc-requirements.maude:69-90",
            "maude/rfc-requirements.maude:1260-1271",
        ],
    ),
    "8446-MUST-0145": _manual_implemented(
        "manual_audit_tls13_encrypted_extensions_early_data_requires_selected_identity_zero",
        [
            "maude/api/connect-v3.maude:291-303",
            "maude/rfc-requirements.maude:543-548",
            "maude/rfc-requirements.maude:1374-1380",
        ],
    ),
    "8446-MUST-0146": _manual_implemented(
        "manual_audit_tls13_encrypted_extensions_early_data_wrong_selected_identity_aborts_illegal_parameter",
        [
            "maude/api/connect-v3.maude:291-303",
            "maude/rfc-requirements.maude:92-97",
            "maude/rfc-requirements.maude:1374-1380",
        ],
    ),
    "8446-MUST-0204": _manual_implemented(
        "manual_audit_tls13_ticket_resumption_requires_same_kdf_hash_as_original_cipher_suite",
        [
            "maude/api/accept-v3.maude:549-556",
            "maude/api/connect-v3.maude:555-568",
            "maude/rfc-requirements.maude:535-564",
        ],
    ),
    "8446-MUST-0209": _manual_implemented(
        "manual_audit_tls13_new_session_ticket_uses_fresh_nonce_from_server_nonce_counter_per_ticket",
        [
            "maude/api/accept-v3.maude:549-556",
            "maude/api/connect-v3.maude:555-568",
            "maude/tls-message.maude:80",
        ],
    ),
    "8446-MUST-0211": _manual_implemented(
        "manual_audit_tls13_post_handshake_auth_client_response_sequence_modeled",
        [
            "maude/api/connect-v3.maude:583-598",
            "maude/api/connect-v3.maude:416-432",
            "maude/api/accept-v3.maude:437-526",
        ],
    ),
    "8446-MUST-0212": _manual_implemented(
        "manual_audit_tls13_post_handshake_auth_certificate_certificateverify_finished_sequence",
        [
            "maude/api/connect-v3.maude:416-526",
            "maude/api/accept-v3.maude:437-526",
        ],
    ),
    "8446-MUST-0213": _manual_implemented(
        "manual_audit_tls13_post_handshake_auth_empty_certificate_then_finished_when_declining",
        [
            "maude/api/connect-v3.maude:416-432",
            "maude/api/accept-v3.maude:426-482",
        ],
    ),
    "8446-MUST-0214": _manual_implemented(
        "manual_audit_tls13_post_handshake_auth_messages_are_consecutive_state_transitions",
        [
            "maude/api/connect-v3.maude:416-526",
            "maude/api/accept-v3.maude:437-526",
        ],
    ),
    "8446-MUST-0215": _manual_implemented(
        "manual_audit_tls13_client_rejects_post_handshake_certificate_request_without_post_handshake_auth",
        [
            "maude/api/connect-v3.maude:606-621",
            "maude/rfc-requirements.maude:1435-1437",
            "maude/rfc-requirements.maude:1824-1827",
        ],
    ),
    "8446-MUST-0217": _manual_implemented(
        "manual_audit_tls13_keyupdate_before_finished_is_unexpected_message_by_state_machine",
        [
            "maude/api/connect-v3.maude:642-721",
            "maude/api/accept-v3.maude:623-714",
            "maude/rfc-requirements.maude:1662-1672",
        ],
    ),
    "8446-MUST-0220": _manual_implemented(
        "manual_audit_tls13_keyupdate_update_requested_sends_update_not_requested_response",
        [
            "maude/api/connect-v3.maude:642-721",
            "maude/api/accept-v3.maude:623-714",
        ],
    ),
    "8446-MUST-0221": _manual_implemented(
        "manual_audit_tls13_keyupdate_messages_written_with_old_write_key_before_key_roll",
        [
            "maude/api/connect-v3.maude:642-672",
            "maude/api/accept-v3.maude:623-653",
        ],
    ),
    "8446-MUST-0222": _manual_implemented(
        "manual_audit_tls13_keyupdate_receiver_state_requires_old_key_message_before_new_key_acceptance",
        [
            "maude/api/connect-v3.maude:690-721",
            "maude/api/accept-v3.maude:677-714",
        ],
    ),
    "8446-MUST-0260": _manual_implemented(
        "manual_audit_tls13_abort_common_forgets_connection_secrets_and_remembers_failed_session",
        [
            "maude/api/common-aux.maude:651-686",
            "maude/api/connect-v3.maude:758-776",
            "maude/api/accept-v3.maude:749-764",
        ],
    ),
    "8446-MUST-0312": _manual_implemented(
        "manual_audit_tls13_early_data_client_rejects_non_tls13_serverhello_on_tls13_path",
        [
            "maude/api/connect-v3.maude:205-241",
            "maude/rfc-requirements.maude:1209-1211",
            "maude/rfc-requirements.maude:1237-1247",
        ],
    ),
    "8446-MUST-0328": _manual_implemented(
        "manual_audit_tls13_early_data_requires_application_requested_early_data_flag",
        [
            "maude/component.maude:238",
            "maude/api/connect-v3.maude:36-55",
            "maude/api/accept-v3.maude:98-160",
        ],
    ),
    "8446-MUST-0329": _manual_implemented(
        "manual_audit_tls13_rejected_early_data_is_discarded_not_automatically_resent",
        [
            "maude/api/accept-v3.maude:145-160",
            "maude/api/connect-v3.maude:114-132",
        ],
    ),
    "8446-MUST-0330": _manual_implemented(
        "manual_audit_tls13_done_states_expose_handshake_completion_to_scenario_layer",
        [
            "maude/handshake-state.maude:61-63",
            "maude/api/connect-v3.maude:548-560",
            "maude/api/accept-v3.maude:542-552",
        ],
    ),
}

MANUAL_COVERAGE_OVERRIDES.update(_TLS13_BATCH_OVERRIDES)


MANUAL_DUPLICATE_EXCLUSIONS = {
    "5246-MUST-0007": "duplicate_of_5246-MUST-0006",
    "5246-MUST-0055": "duplicate_of_5246-MUST-0054",
    "5246-MUST-0056": "duplicate_of_5246-MUST-0054",
    "5246-MUST-0075": "duplicate_of_5246-MUST-0074",
    "5246-MUST-0077": "duplicate_of_5246-MUST-0076",
    "5246-MUST-0105": "duplicate_of_5246-MUST-0104",
    "5246-MUST-0129": "duplicate_of_5246-MUST-0128",
}


MANUAL_SCOPE_EXCLUSIONS = {
    "8446-MUST-0313": "out_of_scope_middlebox_compatibility_not_modeled",
}


def expand_id_specs(rfc: str, specs: list[str]) -> set[str]:
    expanded: set[str] = set()
    for spec in specs:
        if "-" in spec:
            start, end = [int(part) for part in spec.split("-", 1)]
        else:
            start = end = int(spec)
        for value in range(start, end + 1):
            expanded.add(f"{rfc}-MUST-{value:04d}")
    return expanded


def build_classification_map() -> dict[str, str]:
    classification: dict[str, str] = {}
    for rfc, by_class in CLASSIFICATION_SPECS.items():
        for class_name, specs in by_class.items():
            if class_name not in CLASS_LABELS:
                raise ValueError(f"Unknown class {class_name!r}")
            for statement_id in expand_id_specs(rfc, specs):
                if statement_id in classification:
                    raise ValueError(f"Duplicate class assignment for {statement_id}")
                classification[statement_id] = class_name
    return classification


def apply_classification(statements: list[Statement]) -> None:
    classification = build_classification_map()
    statement_ids = {statement.id for statement in statements}
    missing = sorted(statement_ids - set(classification))
    extra = sorted(set(classification) - statement_ids)
    if missing:
        raise ValueError(f"Missing class assignments: {', '.join(missing[:20])}")
    if extra:
        raise ValueError(f"Class assignments for unknown statements: {', '.join(extra[:20])}")

    for statement in statements:
        statement.class_name = classification[statement.id]


def apply_manual_statement_overrides(statements: list[Statement]) -> None:
    by_id = {statement.id: statement for statement in statements}
    for statement_id, override in MANUAL_STATEMENT_OVERRIDES.items():
        statement = by_id.get(statement_id)
        if statement is None:
            raise ValueError(f"Manual statement override references unknown statement: {statement_id}")
        text = override["text"]
        refs = [
            SourceRef(
                raw=f"{file_name}:{start}" if start == end else f"{file_name}:{start}-{end}",
                file=file_name,
                start=start,
                end=end,
            )
            for file_name, start, end in override["source_refs"]
        ]
        spec_lines = read_spec_lines(statement.rfc)
        line_numbers: list[int] = []
        for ref in refs:
            line_numbers.extend(range(ref.start, ref.end + 1))
        statement.statement_text = text
        statement.normalized_text = normalize_text(text)
        statement.source_refs = refs
        statement.source_lines_raw = [spec_lines[line_no - 1] for line_no in line_numbers]


def source_lines_for_refs(refs: list[SourceRef]) -> set[int]:
    lines: set[int] = set()
    for ref in refs:
        lines.update(range(ref.start, ref.end + 1))
    return lines


def apply_seed_coverage(statements: list[Statement], old_rows: list[OldCoverageRow]) -> None:
    rows_by_rfc = {"5246": [], "8446": []}
    for row in old_rows:
        rows_by_rfc[row.rfc].append(row)

    for statement in statements:
        if statement.extraction_status != "included":
            statement.status = "Not Implemented"
            statement.coverage = "excluded"
            statement.reason_code = statement.exclusion_reason or "excluded_from_denominator"
            continue

        statement_lines = source_lines_for_refs(statement.source_refs)
        overlaps: list[OldCoverageRow] = []
        for row in rows_by_rfc[statement.rfc]:
            if statement_lines & source_lines_for_refs(row.source_refs):
                overlaps.append(row)

        if not overlaps:
            statement.status = "Not Implemented"
            statement.coverage = "uncovered"
            statement.reason_code = "no_existing_coverage_mapping"
            continue

        statuses = {row.status for row in overlaps}
        statement.old_row_ids = sorted(row.id for row in overlaps)
        statement.maude_refs = sorted({ref for row in overlaps for ref in row.maude_refs})
        statement.scope = "in_scope_seed"

        if statuses == {"Implemented"}:
            statement.status = "Implemented"
            statement.coverage = "covered"
            statement.reason_code = "old_audit_overlap_implemented"
        elif "Implemented" in statuses or "Partially Implemented" in statuses:
            statement.status = "Partially Implemented"
            statement.coverage = "uncovered"
            statement.reason_code = "old_audit_overlap_partial_or_mixed"
        else:
            statement.status = "Not Implemented"
            statement.coverage = "uncovered"
            statement.reason_code = "old_audit_overlap_not_implemented"


def apply_manual_duplicate_exclusions(statements: list[Statement]) -> None:
    by_id = {statement.id: statement for statement in statements}
    for statement_id, reason in MANUAL_DUPLICATE_EXCLUSIONS.items():
        if statement_id not in by_id:
            raise ValueError(f"Manual duplicate exclusion for unknown statement {statement_id}")
        statement = by_id[statement_id]
        statement.extraction_status = "excluded"
        statement.exclusion_reason = reason
        statement.scope = "excluded_manual_duplicate"
        statement.status = "Not Implemented"
        statement.coverage = "excluded"
        statement.reason_code = reason


def apply_manual_scope_exclusions(statements: list[Statement]) -> None:
    by_id = {statement.id: statement for statement in statements}
    for statement_id, reason in MANUAL_SCOPE_EXCLUSIONS.items():
        if statement_id not in by_id:
            raise ValueError(f"Manual scope exclusion for unknown statement {statement_id}")
        statement = by_id[statement_id]
        statement.extraction_status = "excluded"
        statement.exclusion_reason = reason
        statement.scope = "excluded_manual_scope"
        statement.status = "Not Implemented"
        statement.coverage = "excluded"
        statement.reason_code = reason


def is_manual_duplicate_exclusion(statement: Statement) -> bool:
    return statement.extraction_status == "excluded" and statement.exclusion_reason.startswith("duplicate_of_")


def apply_manual_coverage_overrides(statements: list[Statement]) -> None:
    by_id = {statement.id: statement for statement in statements}
    for statement_id, override in MANUAL_COVERAGE_OVERRIDES.items():
        if statement_id not in by_id:
            raise ValueError(f"Manual coverage override for unknown statement {statement_id}")
        statement = by_id[statement_id]
        statement.status = override["status"]
        statement.coverage = override["coverage"]
        statement.scope = override["scope"]
        statement.reason_code = override["reason_code"]
        if override.get("replace_maude_refs"):
            statement.maude_refs = sorted(set(override["maude_refs"]))
        else:
            statement.maude_refs = sorted(set(statement.maude_refs) | set(override["maude_refs"]))
        statement.old_row_ids = sorted(set(statement.old_row_ids) | set(override["old_row_ids"]))


def rendered_html_line(line: str) -> str:
    return html.unescape(TAG_RE.sub("", line)).rstrip()


def compact_line(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def line_text_matches(rendered: str, target: str) -> bool:
    target_rstrip = target.rstrip()
    if rendered.rstrip() == target_rstrip:
        return True
    return bool(target_rstrip and compact_line(rendered) == compact_line(target))


def should_wrap_html_line(line: str) -> bool:
    stripped = line.lstrip()
    if stripped.startswith("<h") and re.match(r"<h[1-6]\b", stripped):
        return False
    if stripped.startswith("<pre") or stripped.startswith("<div") or stripped.startswith("</"):
        return False
    return True


def context_match_score(rendered_lines: list[str], spec_lines: list[str], source_line_no: int, html_idx: int, window: int = 8) -> int:
    score = 0
    source_idx = source_line_no - 1
    for delta in range(-window, window + 1):
        if delta == 0:
            continue
        spec_idx = source_idx + delta
        candidate_idx = html_idx + delta
        if spec_idx < 0 or spec_idx >= len(spec_lines):
            continue
        if candidate_idx < 0 or candidate_idx >= len(rendered_lines):
            continue
        spec_text = spec_lines[spec_idx].rstrip("\r\n")
        if not spec_text.strip():
            continue
        if line_text_matches(rendered_lines[candidate_idx], spec_text):
            score += window + 1 - abs(delta)
    return score


def find_rendered_line_for_source(
    rendered_lines: list[str],
    html_lines: list[str],
    spec_lines: list[str],
    source_line_no: int,
    search_pos: int,
    used_html_indices: set[int],
) -> tuple[int, str]:
    target = spec_lines[source_line_no - 1].rstrip("\r\n")
    candidates = [
        idx
        for idx, rendered in enumerate(rendered_lines)
        if idx not in used_html_indices
        and should_wrap_html_line(html_lines[idx])
        and line_text_matches(rendered, target)
    ]
    if not candidates:
        return -1, "none"
    after_candidates = [idx for idx in candidates if idx >= search_pos]
    pool = after_candidates or candidates
    method = "forward-context" if after_candidates else "global-context"
    best_idx = max(
        pool,
        key=lambda idx: (
            context_match_score(rendered_lines, spec_lines, source_line_no, idx),
            -abs(idx - search_pos),
        ),
    )
    return best_idx, method


def line_groups_for_rfc(statements: list[Statement], rfc: str) -> dict[int, dict[str, Any]]:
    groups: dict[int, dict[str, Any]] = {}
    for statement in statements:
        if statement.rfc != rfc:
            continue
        if is_manual_duplicate_exclusion(statement):
            continue
        for ref in statement.source_refs:
            spec_lines = read_spec_lines(rfc)
            for line_no in range(ref.start, ref.end + 1):
                if is_page_artifact(spec_lines[line_no - 1], rfc):
                    continue
                groups.setdefault(line_no, {"ids": [], "text": spec_lines[line_no - 1]})
                if statement.id not in groups[line_no]["ids"]:
                    groups[line_no]["ids"].append(statement.id)
    return groups


def annotate_rfc_html(statements: list[Statement], rfc: str) -> tuple[str, dict[str, Any]]:
    raw_path = RAW_DIR / f"rfc{rfc}.html"
    html_text = raw_path.read_text(encoding="utf-8", errors="replace")
    start = html_text.find('<div class="rfcmarkup">')
    end = html_text.find("</div>", start)
    if start == -1 or end == -1:
        raise ValueError(f"Could not locate rfcmarkup content in {raw_path}")

    content = html_text[start:end]
    html_lines = content.split("\n")
    rendered_lines = [rendered_html_line(line) for line in html_lines]
    spec_lines = read_spec_lines(rfc)
    by_id = {statement.id: statement for statement in statements}
    line_groups = line_groups_for_rfc(statements, rfc)
    used_html_indices: set[int] = set()
    search_pos = 0
    unmatched: list[dict[str, Any]] = []
    matched_lines = 0

    for line_no in sorted(line_groups):
        group = line_groups[line_no]
        text = group["text"].rstrip("\r\n")
        ids = sorted(group["ids"])
        if not text.strip():
            continue
        idx, match_method = find_rendered_line_for_source(
            rendered_lines=rendered_lines,
            html_lines=html_lines,
            spec_lines=spec_lines,
            source_line_no=line_no,
            search_pos=search_pos,
            used_html_indices=used_html_indices,
        )
        if idx == -1:
            for statement_id in ids:
                by_id[statement_id].unmatched_lines.append({"line": line_no, "text": text})
            unmatched.append({"line": line_no, "ids": ids, "text": text})
            continue

        included_ids = [
            statement_id
            for statement_id in ids
            if by_id[statement_id].extraction_status != "excluded"
        ]
        if not included_ids:
            coverage = "excluded"
        else:
            coverages = {by_id[statement_id].coverage for statement_id in included_ids}
            coverage = "covered" if coverages == {"covered"} else "uncovered"
        keywords = sorted({by_id[statement_id].keyword for statement_id in ids})
        class_names = sorted({by_id[statement_id].class_name for statement_id in ids})
        attrs = {
            "class": f"mustcov coverage-{coverage}",
            "data-mustcov-ids": ",".join(ids),
            "data-mustcov-coverage": coverage,
            "data-mustcov-keywords": ",".join(keywords),
            "data-mustcov-classes": ",".join(class_names),
            "data-mustcov-line": str(line_no),
            "data-mustcov-match": match_method,
            "tabindex": "0",
        }
        attr_text = " ".join(f'{key}="{html.escape(value, quote=True)}"' for key, value in attrs.items())
        html_lines[idx] = f"<span {attr_text}>{html_lines[idx]}</span>"
        rendered_lines[idx] = rendered_html_line(html_lines[idx])
        used_html_indices.add(idx)
        search_pos = idx + 1
        matched_lines += 1
        for statement_id in ids:
            by_id[statement_id].matched_lines += 1

    data = per_rfc_data(statements, rfc, matched_lines, unmatched, raw_path)
    annotated = html_text[:start] + "\n".join(html_lines) + html_text[end:]
    annotated = inject_assets(annotated, rfc, data)
    return annotated, {"rfc": rfc, "unmatched": unmatched, "data": data}


def summarize(statements: list[Statement]) -> dict[str, Any]:
    included = [statement for statement in statements if statement.extraction_status == "included"]
    by_class: dict[str, dict[str, Any]] = {
        class_name: {
            "label": label,
            "candidates": 0,
            "included": 0,
            "excluded": 0,
            "covered": 0,
            "uncovered": 0,
            "byStatus": {},
        }
        for class_name, label in CLASS_LABELS.items()
    }
    summary: dict[str, Any] = {
        "totalCandidates": len(statements),
        "includedStatements": len(included),
        "excludedCandidates": len([s for s in statements if s.extraction_status == "excluded"]),
        "duplicateClusterMembers": len([s for s in statements if s.dedupe_cluster]),
        "byCoverage": {},
        "byStatus": {},
        "byKeyword": {},
        "byBlockType": {},
        "byClass": by_class,
    }
    for statement in statements:
        class_counts = by_class[statement.class_name]
        class_counts["candidates"] += 1
        if statement.extraction_status == "excluded":
            class_counts["excluded"] += 1
            continue
        class_counts["included"] += 1
        class_counts[statement.coverage] += 1
        class_counts["byStatus"][statement.status] = class_counts["byStatus"].get(statement.status, 0) + 1

        summary["byCoverage"][statement.coverage] = summary["byCoverage"].get(statement.coverage, 0) + 1
        summary["byStatus"][statement.status] = summary["byStatus"].get(statement.status, 0) + 1
        summary["byKeyword"][statement.keyword] = summary["byKeyword"].get(statement.keyword, 0) + 1
        summary["byBlockType"][statement.block_type] = summary["byBlockType"].get(statement.block_type, 0) + 1
    return summary


def per_rfc_data(statements: list[Statement], rfc: str, matched_lines: int, unmatched: list[dict[str, Any]], raw_path: Path) -> dict[str, Any]:
    rows = [statement for statement in statements if statement.rfc == rfc and not is_manual_duplicate_exclusion(statement)]
    return {
        "schema": "rfc-must-coverage-viewer-v1",
        "rfc": rfc,
        "classDefinitions": CLASS_LABELS,
        "classOrder": CLASS_ORDER,
        "source": {
            "html": f"https://datatracker.ietf.org/doc/html/rfc{rfc}",
            "rawPath": str(raw_path.relative_to(ROOT)),
        },
        "summary": summarize(rows),
        "matchSummary": {
            "matchedLines": matched_lines,
            "unmatchedLines": len(unmatched),
            "citedNonBlankLines": matched_lines + len(unmatched),
            "statementsWithUnmatchedLines": len([statement for statement in rows if statement.unmatched_lines]),
        },
        "statements": [statement.to_json() for statement in rows],
    }


def inject_assets(html_text: str, rfc: str, data: dict[str, Any]) -> str:
    css_tag = '<link rel="stylesheet" href="must-coverage.css">\n'
    if "must-coverage.css" not in html_text:
        html_text = html_text.replace("</head>", f"{css_tag}</head>", 1)

    data_json = (
        json.dumps(data, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
    )
    script_tags = (
        f'<script id="mustcov-data" type="application/json" data-rfc="{rfc}">{data_json}</script>\n'
        '<script src="must-coverage.js"></script>\n'
    )
    html_text = re.sub(r"<script>\(function\(\).*?</script></body>", "</body>", html_text, flags=re.S)
    if "must-coverage.js" not in html_text:
        html_text = html_text.replace("</body>", f"{script_tags}</body>", 1)
    return html_text


def write_json_artifacts(statements: list[Statement], per_rfc: list[dict[str, Any]]) -> None:
    viewer_statements = [statement for statement in statements if not is_manual_duplicate_exclusion(statement)]
    data = {
        "schema": "rfc-must-statements-v1",
        "generation": {
            "method": "explicit uppercase MUST/MUST NOT sentence extraction from local RFC text; coverage seeded by overlap with denominator-v1.md/numerator-v1.md",
            "class": "single semantic class per extracted statement",
            "coveredDefinition": "coverage=covered iff status=Implemented",
        },
        "classDefinitions": CLASS_LABELS,
        "classOrder": CLASS_ORDER,
        "summary": summarize(statements),
        "rfcs": {item["rfc"]: item["data"]["matchSummary"] for item in per_rfc},
        "statements": [statement.to_json() for statement in statements],
    }
    viewer_data = {
        **data,
        "summary": summarize(viewer_statements),
        "statements": [statement.to_json() for statement in viewer_statements],
    }
    OUT_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    OUT_VIEWER_JSON.write_text(json.dumps(viewer_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def markdown_table_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def write_markdown(statements: list[Statement]) -> None:
    lines = [
        "# RFC 5246/8446 Explicit MUST/MUST NOT Statement Inventory v1",
        "",
        "This inventory is generated from explicit uppercase `MUST` and `MUST NOT` statements in the local RFC text files.",
        "Each candidate is assigned exactly one semantic class. Coverage is a conservative seed derived from source-line overlap with the previous RFC-check audit.",
        "",
        "## Summary",
        "",
        "| Scope | Candidates | Included | Covered | Uncovered |",
        "|---|---:|---:|---:|---:|",
    ]
    for rfc in ("5246", "8446", "all"):
        rows = statements if rfc == "all" else [statement for statement in statements if statement.rfc == rfc]
        included = [statement for statement in rows if statement.extraction_status == "included"]
        covered = [statement for statement in included if statement.coverage == "covered"]
        lines.append(f"| RFC {rfc.upper() if rfc != 'all' else 'total'} | {len(rows)} | {len(included)} | {len(covered)} | {len(included) - len(covered)} |")

    lines.extend([
        "",
        "## Class Summary",
        "",
        "| Scope | Class | Included | Covered | Uncovered | Excluded candidates |",
        "|---|---|---:|---:|---:|---:|",
    ])
    for rfc in ("5246", "8446", "all"):
        rows = statements if rfc == "all" else [statement for statement in statements if statement.rfc == rfc]
        summary = summarize(rows)
        scope = f"RFC {rfc.upper()}" if rfc != "all" else "RFC total"
        for class_name in CLASS_ORDER:
            counts = summary["byClass"][class_name]
            lines.append(
                f"| {scope} | {CLASS_LABELS[class_name]} | {counts['included']} | {counts['covered']} | {counts['uncovered']} | {counts['excluded']} |"
            )

    lines.extend([
        "",
        "## Included Statements",
        "",
        "| ID | RFC | Keyword | Class | Section | Source lines | Coverage | Status | Reason code | Maude refs | Statement |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ])
    for statement in statements:
        if statement.extraction_status != "included":
            continue
        refs = ", ".join(f"`{ref.raw}`" for ref in statement.source_refs)
        maude = ", ".join(f"`{ref}`" for ref in statement.maude_refs) if statement.maude_refs else ""
        section = f"{statement.section_id} {statement.section_title}".strip()
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{statement.id}`",
                    statement.rfc,
                    f"`{statement.keyword}`",
                    CLASS_LABELS[statement.class_name],
                    markdown_table_escape(section),
                    refs,
                    statement.coverage,
                    statement.status,
                    f"`{statement.reason_code}`",
                    maude,
                    markdown_table_escape(statement.statement_text),
                ]
            )
            + " |"
        )

    lines.extend([
        "",
        "## Excluded Candidates",
        "",
        "| ID | RFC | Keyword | Class | Section | Source lines | Extraction status | Reason | Statement |",
        "|---|---|---|---|---|---|---|---|---|",
    ])
    for statement in statements:
        if statement.extraction_status == "included":
            continue
        refs = ", ".join(f"`{ref.raw}`" for ref in statement.source_refs)
        section = f"{statement.section_id} {statement.section_title}".strip()
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{statement.id}`",
                    statement.rfc,
                    f"`{statement.keyword}`",
                    CLASS_LABELS[statement.class_name],
                    markdown_table_escape(section),
                    refs,
                    statement.extraction_status,
                    f"`{statement.exclusion_reason}`",
                    markdown_table_escape(statement.statement_text),
                ]
            )
            + " |"
        )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_classification_artifacts(statements: list[Statement]) -> None:
    summary = {
        "schema": "rfc-must-classification-v1",
        "classDefinitions": CLASS_LABELS,
        "classOrder": CLASS_ORDER,
        "summary": summarize(statements),
        "byRfc": {
            rfc: summarize([statement for statement in statements if statement.rfc == rfc])
            for rfc in ("5246", "8446")
        },
        "assignments": [
            {
                "id": statement.id,
                "rfc": statement.rfc,
                "keyword": statement.keyword,
                "class": statement.class_name,
                "classLabel": CLASS_LABELS[statement.class_name],
                "coverage": statement.coverage,
                "status": statement.status,
                "extractionStatus": statement.extraction_status,
                "sourceRefs": [ref.to_json() for ref in statement.source_refs],
                "text": statement.statement_text,
            }
            for statement in statements
            if not is_manual_duplicate_exclusion(statement)
        ],
    }
    OUT_CLASS_JSON.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# RFC MUST/MUST NOT Classification v1",
        "",
        "Each extracted candidate is assigned exactly one class. Counts below use included statements for covered/uncovered and list excluded terminology candidates separately.",
        "",
        "## Class Counts",
        "",
        "| Scope | Class | Included | Covered | Uncovered | Excluded candidates |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for rfc in ("5246", "8446", "all"):
        rows = statements if rfc == "all" else [statement for statement in statements if statement.rfc == rfc]
        scope = f"RFC {rfc.upper()}" if rfc != "all" else "RFC total"
        by_class = summarize(rows)["byClass"]
        for class_name in CLASS_ORDER:
            counts = by_class[class_name]
            lines.append(
                f"| {scope} | {CLASS_LABELS[class_name]} | {counts['included']} | {counts['covered']} | {counts['uncovered']} | {counts['excluded']} |"
            )

    lines.extend([
        "",
        "## Assignments",
        "",
        "| ID | RFC | Class | Coverage | Status | Source lines | Statement |",
        "|---|---|---|---|---|---|---|",
    ])
    for statement in statements:
        if is_manual_duplicate_exclusion(statement):
            continue
        refs = ", ".join(f"`{ref.raw}`" for ref in statement.source_refs)
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{statement.id}`",
                    statement.rfc,
                    CLASS_LABELS[statement.class_name],
                    statement.coverage,
                    statement.status,
                    refs,
                    markdown_table_escape(statement.statement_text),
                ]
            )
            + " |"
        )
    OUT_CLASS_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_mapping_report(per_rfc: list[dict[str, Any]]) -> None:
    lines = [
        "# RFC MUST Coverage Mapping Report",
        "",
        "This report lists extracted MUST/MUST NOT source lines that were not mapped into the downloaded datatracker HTML.",
        "",
    ]
    for item in per_rfc:
        rfc = item["rfc"]
        data = item["data"]
        unmatched = item["unmatched"]
        lines.extend(
            [
                f"## RFC {rfc}",
                "",
                f"- Matched cited nonblank lines: {data['matchSummary']['matchedLines']}",
                f"- Unmatched cited nonblank lines: {data['matchSummary']['unmatchedLines']}",
                f"- Statements with unmatched lines: {data['matchSummary']['statementsWithUnmatchedLines']}",
                "",
            ]
        )
        if not unmatched:
            lines.extend(["No unmatched cited lines.", ""])
            continue
        for entry in unmatched:
            ids = ", ".join(f"`{statement_id}`" for statement_id in entry["ids"])
            lines.append(f"- line {entry['line']}: {ids}")
        lines.append("")
    OUT_MAPPING_REPORT.write_text("\n".join(lines), encoding="utf-8")


def write_index(per_rfc: list[dict[str, Any]]) -> None:
    cards = []
    for item in per_rfc:
        rfc = item["rfc"]
        summary = item["data"]["summary"]
        match = item["data"]["matchSummary"]
        covered = summary["byCoverage"].get("covered", 0)
        uncovered = summary["byCoverage"].get("uncovered", 0)
        class_rows = []
        for class_name in CLASS_ORDER:
            counts = summary["byClass"][class_name]
            class_rows.append(
                f"<div><span>{html.escape(CLASS_LABELS[class_name])}</span>"
                f"<strong>{counts['covered']} covered / {counts['uncovered']} uncovered</strong></div>"
            )
        cards.append(
            f'<a class="mustcov-index-card" href="rfc{rfc}-must-coverage.html">'
            f"<strong>RFC {rfc}</strong>"
            f"<span>{summary['totalCandidates']} candidates · {summary['includedStatements']} included</span>"
            f"<span>{covered} covered / {uncovered} uncovered</span>"
            f"<small>{match['matchedLines']} matched lines / {match['unmatchedLines']} unmatched</small>"
            f"<div class=\"mustcov-index-class-list\">{''.join(class_rows)}</div>"
            "</a>"
        )
    index = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RFC MUST Coverage Viewer</title>
  <link rel="stylesheet" href="must-coverage.css">
</head>
<body class="mustcov-index">
  <main>
    <h1>RFC MUST Coverage Viewer</h1>
    <p>Explicit RFC 5246/8446 MUST and MUST NOT statements, each assigned to exactly one semantic class.</p>
    <div class="mustcov-index-grid">
      {''.join(cards)}
    </div>
    <p><a href="mapping-report.md">Mapping report</a> · <a href="must-coverage-data.json">Coverage data</a> · <a href="../must-statements-v1.md">Statement inventory</a> · <a href="../must-classification-v1.md">Classification table</a></p>
  </main>
</body>
</html>
"""
    (VIEWER_DIR / "index.html").write_text(index, encoding="utf-8")


def write_static_assets() -> None:
    (VIEWER_DIR / "must-coverage.css").write_text(MUST_COVERAGE_CSS, encoding="utf-8")
    (VIEWER_DIR / "must-coverage.js").write_text(MUST_COVERAGE_JS, encoding="utf-8")


MUST_COVERAGE_CSS = r""":root {
  --mustcov-panel-bg: #ffffff;
  --mustcov-panel-text: #0f172a;
  --mustcov-border: #cbd5e1;
  --mustcov-muted: #475569;
  --mustcov-covered-bg: #dbeafe;
  --mustcov-covered-text: #1d4ed8;
  --mustcov-uncovered-bg: #fee2e2;
  --mustcov-uncovered-text: #991b1b;
}

[data-bs-theme="dark"] {
  --mustcov-panel-bg: #0f172a;
  --mustcov-panel-text: #f8fafc;
  --mustcov-border: #334155;
  --mustcov-muted: #cbd5e1;
  --mustcov-covered-bg: #172554;
  --mustcov-covered-text: #bfdbfe;
  --mustcov-uncovered-bg: #7f1d1d;
  --mustcov-uncovered-text: #fee2e2;
  --mustcov-excluded-bg: #334155;
  --mustcov-excluded-text: #e2e8f0;
}

.mustcov {
  border-radius: 3px;
  box-decoration-break: clone;
  cursor: pointer;
  outline-offset: 2px;
  scroll-margin-top: 5rem;
}

.mustcov.coverage-covered {
  background: var(--mustcov-covered-bg);
  color: var(--mustcov-covered-text);
}

.mustcov.coverage-uncovered {
  background: var(--mustcov-uncovered-bg);
  color: var(--mustcov-uncovered-text);
}

.mustcov.coverage-excluded {
  background: var(--mustcov-excluded-bg);
  color: var(--mustcov-excluded-text);
}

.mustcov.is-active,
.mustcov:focus {
  outline: 2px solid #2563eb;
}

.mustcov.is-hidden {
  background: transparent;
  color: inherit;
}

#mustcov-panel {
  position: fixed;
  z-index: 10000;
  top: 0;
  right: 0;
  bottom: 0;
  width: min(440px, 100vw);
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 1rem;
  background: var(--mustcov-panel-bg);
  color: var(--mustcov-panel-text);
  border-left: 1px solid var(--mustcov-border);
  box-shadow: -12px 0 32px rgba(15, 23, 42, 0.16);
  font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  overflow: auto;
}

#mustcov-panel h2 {
  margin: 0;
  font-size: 1.1rem;
}

.mustcov-muted {
  color: var(--mustcov-muted);
}

.mustcov-panel-head {
  display: flex;
  justify-content: space-between;
  gap: 0.75rem;
  align-items: start;
}

.mustcov-close {
  width: 2rem;
  height: 2rem;
  border: 1px solid var(--mustcov-border);
  border-radius: 6px;
  background: transparent;
  color: inherit;
  cursor: pointer;
}

.mustcov-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(4.8rem, 1fr));
  gap: 0.35rem;
}

.mustcov-summary div {
  border: 1px solid var(--mustcov-border);
  border-radius: 6px;
  padding: 0.45rem;
}

.mustcov-summary strong,
.mustcov-summary span {
  display: block;
}

.mustcov-summary span {
  color: var(--mustcov-muted);
  font-size: 0.72rem;
}

.mustcov-controls {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}

.mustcov-controls label {
  display: grid;
  gap: 0.25rem;
  color: var(--mustcov-muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.mustcov-controls input,
.mustcov-controls select {
  min-width: 0;
  border: 1px solid var(--mustcov-border);
  border-radius: 6px;
  padding: 0.4rem 0.5rem;
  background: var(--mustcov-panel-bg);
  color: var(--mustcov-panel-text);
  font: inherit;
  text-transform: none;
  letter-spacing: 0;
}

.mustcov-search {
  grid-column: 1 / -1;
}

.mustcov-detail {
  border: 1px solid var(--mustcov-border);
  border-radius: 8px;
  padding: 0.75rem;
}

.mustcov-detail.is-empty {
  color: var(--mustcov-muted);
}

.mustcov-detail h3 {
  margin: 0 0 0.5rem;
  font-size: 1rem;
}

.mustcov-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-bottom: 0.55rem;
}

.mustcov-badge {
  border-radius: 999px;
  padding: 0.12rem 0.5rem;
  font-size: 0.75rem;
  font-weight: 700;
  border: 1px solid var(--mustcov-border);
}

.mustcov-badge.coverage-covered {
  background: var(--mustcov-covered-bg);
  color: var(--mustcov-covered-text);
}

.mustcov-badge.coverage-uncovered {
  background: var(--mustcov-uncovered-bg);
  color: var(--mustcov-uncovered-text);
}

.mustcov-badge.coverage-excluded {
  background: var(--mustcov-excluded-bg);
  color: var(--mustcov-excluded-text);
}

.mustcov-detail dl {
  display: grid;
  grid-template-columns: 7rem 1fr;
  gap: 0.35rem 0.5rem;
  margin: 0;
}

.mustcov-detail dt {
  color: var(--mustcov-muted);
  font-weight: 700;
}

.mustcov-detail dd {
  margin: 0;
}

.mustcov-detail code {
  overflow-wrap: anywhere;
}

.mustcov-list {
  display: grid;
  gap: 0.35rem;
}

.mustcov-list button {
  display: grid;
  grid-template-columns: 8.5rem 1fr;
  gap: 0.5rem;
  text-align: left;
  border: 1px solid var(--mustcov-border);
  border-radius: 6px;
  padding: 0.45rem 0.55rem;
  background: transparent;
  color: inherit;
  cursor: pointer;
}

.mustcov-list button:hover,
.mustcov-list button.is-selected {
  border-color: #2563eb;
}

.mustcov-list span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mustcov-index {
  margin: 0;
  background: #f8fafc;
  color: #0f172a;
  font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.mustcov-index main {
  max-width: 1100px;
  margin: 4rem auto;
  padding: 0 1rem;
}

.mustcov-index-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1rem;
}

.mustcov-index-card {
  display: grid;
  gap: 0.25rem;
  padding: 1rem;
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  background: #ffffff;
  color: inherit;
  text-decoration: none;
}

.mustcov-index-card span,
.mustcov-index-card small {
  color: #475569;
}

.mustcov-index-class-list {
  display: grid;
  gap: 0.2rem;
  margin-top: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid #e2e8f0;
}

.mustcov-index-class-list div {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 0.5rem;
  align-items: baseline;
  font-size: 0.82rem;
}

.mustcov-index-class-list strong {
  font-size: 0.78rem;
  color: #0f172a;
}
"""


MUST_COVERAGE_JS = r"""(function () {
  "use strict";

  const dataEl = document.getElementById("mustcov-data");
  if (!dataEl) return;

  const data = JSON.parse(dataEl.textContent || "{}");
  const statements = data.statements || [];
  const classDefinitions = data.classDefinitions || {};
  const classOrder = data.classOrder || Object.keys(classDefinitions);
  const classOptionsHtml = classOrder
    .map((className) => `<option value="${escapeHtml(className)}">${escapeHtml(classDefinitions[className] || className)}</option>`)
    .join("");
  const byId = new Map(statements.map((item) => [item.id, item]));
  const spans = Array.from(document.querySelectorAll(".mustcov"));
  const spansById = new Map();

  for (const span of spans) {
    const ids = (span.dataset.mustcovIds || "").split(",").filter(Boolean);
    for (const id of ids) {
      if (!spansById.has(id)) spansById.set(id, []);
      spansById.get(id).push(span);
    }
  }

  const panel = document.createElement("aside");
  panel.id = "mustcov-panel";
  panel.innerHTML = `
    <div class="mustcov-panel-head">
      <div>
        <h2>MUST Coverage</h2>
        <div class="mustcov-muted">RFC ${escapeHtml(data.rfc || "")} · semantic class filter</div>
      </div>
      <button class="mustcov-close" type="button" aria-label="Close coverage panel">x</button>
    </div>
    <div class="mustcov-summary"></div>
    <div class="mustcov-controls">
      <label class="mustcov-search">Search
        <input type="search" data-mustcov-filter="search" placeholder="ID, statement, source line, Maude ref">
      </label>
      <label>Coverage
        <select data-mustcov-filter="coverage">
          <option value="">All</option>
          <option value="covered">Covered</option>
          <option value="uncovered">Uncovered</option>
          <option value="excluded">Excluded</option>
        </select>
      </label>
      <label>Keyword
        <select data-mustcov-filter="keyword">
          <option value="">All</option>
          <option value="MUST">MUST</option>
          <option value="MUST NOT">MUST NOT</option>
        </select>
      </label>
      <label>Class
        <select data-mustcov-filter="class">
          <option value="">All</option>
          ${classOptionsHtml}
        </select>
      </label>
    </div>
    <div class="mustcov-detail is-empty">Select a highlighted MUST/MUST NOT line or a row below.</div>
    <div class="mustcov-list"></div>
  `;
  document.body.appendChild(panel);

  const summaryEl = panel.querySelector(".mustcov-summary");
  const detailEl = panel.querySelector(".mustcov-detail");
  const listEl = panel.querySelector(".mustcov-list");
  const searchEl = panel.querySelector('[data-mustcov-filter="search"]');
  const coverageEl = panel.querySelector('[data-mustcov-filter="coverage"]');
  const keywordEl = panel.querySelector('[data-mustcov-filter="keyword"]');
  const classEl = panel.querySelector('[data-mustcov-filter="class"]');
  const closeEl = panel.querySelector(".mustcov-close");

  let selectedId = null;
  let filtered = statements.slice();

  renderSummary(filtered);
  renderList();
  bindEvents();
  openInitialHash();

  function renderSummary(items) {
    const included = items.filter((item) => item.extractionStatus !== "excluded");
    const counts = countCoverage(included);
    summaryEl.innerHTML = `
      <div><strong>${items.length}</strong><span>candidates</span></div>
      <div><strong>${included.length}</strong><span>included</span></div>
      <div><strong>${counts.covered || 0}</strong><span>covered</span></div>
      <div><strong>${counts.uncovered || 0}</strong><span>uncovered</span></div>
      <div><strong>${countExcluded(items)}</strong><span>excluded</span></div>
    `;
  }

  function renderList() {
    listEl.innerHTML = "";
    for (const item of filtered) {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.mustcovRow = item.id;
      button.className = item.id === selectedId ? "is-selected" : "";
      button.innerHTML = `<code>${escapeHtml(item.id)}</code><span>${escapeHtml(item.keyword)} · ${escapeHtml(classLabel(item))} · ${escapeHtml(sectionLabel(item))}</span>`;
      listEl.appendChild(button);
    }
  }

  function bindEvents() {
    for (const span of spans) {
      span.addEventListener("click", () => {
        const id = firstId(span);
        if (id) selectStatement(id, true);
      });
      span.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          const id = firstId(span);
          if (id) selectStatement(id, true);
        }
      });
    }

    listEl.addEventListener("click", (event) => {
      const button = event.target.closest("[data-mustcov-row]");
      if (button) selectStatement(button.dataset.mustcovRow, true);
    });

    for (const input of [searchEl, coverageEl, keywordEl, classEl]) {
      input.addEventListener("input", applyFilters);
      input.addEventListener("change", applyFilters);
    }

    closeEl.addEventListener("click", () => {
      panel.style.display = "none";
    });
  }

  function openInitialHash() {
    const hash = decodeURIComponent(window.location.hash.replace(/^#must-/, ""));
    if (hash && byId.has(hash)) selectStatement(hash, true);
  }

  function selectStatement(id, scroll) {
    const item = byId.get(id);
    if (!item) return;
    selectedId = id;
    panel.style.display = "";

    for (const span of spans) span.classList.remove("is-active");
    const selectedSpans = spansById.get(id) || [];
    for (const span of selectedSpans) span.classList.add("is-active");

    detailEl.className = "mustcov-detail";
    detailEl.innerHTML = renderDetail(item);
    renderList();

    if (scroll && selectedSpans[0]) {
      selectedSpans[0].scrollIntoView({ block: "center", behavior: "smooth" });
      history.replaceState(null, "", `#must-${id}`);
    }
  }

  function renderDetail(item) {
    const refs = (item.sourceRefs || []).map((ref) => `${ref.file}:${ref.start}${ref.end !== ref.start ? `-${ref.end}` : ""}`).join(", ");
    const maude = (item.maudeRefs || []).map((ref) => `<code>${escapeHtml(ref)}</code>`).join("<br>") || "None";
    const oldRows = (item.oldCoverageRows || []).map((id) => `<code>${escapeHtml(id)}</code>`).join(", ") || "None";
    return `
      <h3>${escapeHtml(item.id)}</h3>
      <div class="mustcov-badges">
        <span class="mustcov-badge coverage-${escapeHtml(item.coverage)}">${escapeHtml(item.coverage)}</span>
        <span class="mustcov-badge">${escapeHtml(item.status)}</span>
        <span class="mustcov-badge">${escapeHtml(item.keyword)}</span>
        <span class="mustcov-badge">${escapeHtml(classLabel(item))}</span>
      </div>
      <dl>
        <dt>Class</dt><dd>${escapeHtml(classLabel(item))}</dd>
        <dt>Section</dt><dd>${escapeHtml(sectionLabel(item))}</dd>
        <dt>Source lines</dt><dd>${escapeHtml(refs)}</dd>
        <dt>Statement</dt><dd>${escapeHtml(item.text)}</dd>
        <dt>Reason</dt><dd><code>${escapeHtml(item.reasonCode)}</code></dd>
        <dt>Extraction</dt><dd>${escapeHtml(item.extractionStatus)}${item.exclusionReason ? ` · <code>${escapeHtml(item.exclusionReason)}</code>` : ""}</dd>
        <dt>Old rows</dt><dd>${oldRows}</dd>
        <dt>Maude refs</dt><dd>${maude}</dd>
      </dl>
    `;
  }

  function applyFilters() {
    const query = searchEl.value.trim().toLowerCase();
    const coverage = coverageEl.value;
    const keyword = keywordEl.value;
    const className = classEl.value;

    filtered = statements.filter((item) => {
      if (coverage && item.coverage !== coverage) return false;
      if (keyword && item.keyword !== keyword) return false;
      if (className && item.class !== className) return false;
      if (query) {
        const refs = (item.sourceRefs || []).map((ref) => `${ref.file}:${ref.start}${ref.end !== ref.start ? `-${ref.end}` : ""}`);
        const haystack = [
          item.id,
          item.keyword,
          item.class,
          classLabel(item),
          item.text,
          sectionLabel(item),
          item.reasonCode,
          ...refs,
          ...(item.maudeRefs || []),
          ...(item.oldCoverageRows || []),
        ].join(" ").toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });

    const visibleIds = new Set(filtered.map((item) => item.id));
    for (const span of spans) {
      const ids = (span.dataset.mustcovIds || "").split(",").filter(Boolean);
      const visible = ids.some((id) => visibleIds.has(id));
      span.classList.toggle("is-hidden", !visible);
    }

    renderSummary(filtered);
    renderList();
  }

  function firstId(span) {
    return (span.dataset.mustcovIds || "").split(",").filter(Boolean)[0];
  }

  function countCoverage(items) {
    return items.reduce((acc, item) => {
      acc[item.coverage] = (acc[item.coverage] || 0) + 1;
      return acc;
    }, {});
  }

  function countExcluded(items) {
    return items.filter((item) => item.extractionStatus === "excluded").length;
  }

  function sectionLabel(item) {
    const section = item.section || {};
    return `${section.id || ""} ${section.title || ""}`.trim();
  }

  function classLabel(item) {
    return item.classLabel || classDefinitions[item.class] || item.class || "";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
"""


def build() -> None:
    statements = extract_statements()
    apply_manual_statement_overrides(statements)
    apply_classification(statements)
    apply_manual_duplicate_exclusions(statements)
    old_rows = parse_old_coverage()
    apply_seed_coverage(statements, old_rows)
    apply_manual_coverage_overrides(statements)
    apply_manual_scope_exclusions(statements)

    per_rfc = []
    for rfc in ("5246", "8446"):
        annotated, result = annotate_rfc_html(statements, rfc)
        (VIEWER_DIR / f"rfc{rfc}-must-coverage.html").write_text(annotated, encoding="utf-8")
        per_rfc.append(result)

    write_static_assets()
    write_json_artifacts(statements, per_rfc)
    write_markdown(statements)
    write_classification_artifacts(statements)
    write_mapping_report(per_rfc)
    write_index(per_rfc)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    build()


if __name__ == "__main__":
    main()
