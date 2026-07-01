#!/usr/bin/env python3
"""Build annotated RFC coverage HTML pages.

The generator joins denominator-v1.md and numerator-v1.md by RFC-check ID,
resolves denominator source-line references against the local RFC text files,
and wraps matching lines in downloaded datatracker HTML copies.
"""

from __future__ import annotations

import argparse
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

CLASS_BY_PREFIX = {
    "SYN": ("syntax", "Syntax/length check"),
    "STA": ("state", "Message order expectation"),
    "EXT": ("extension", "Extension validity"),
    "NEG": ("negotiation", "Negotiation consistency"),
    "AUTH": ("auth", "Authentication validation"),
    "CTX": ("ctx", "Cryptographic-context validation"),
    "SESS": ("sess", "Session/resumption/post-handshake validation"),
}

STATUS_ORDER = {
    "not implemented": 3,
    "partial": 2,
    "implemented": 1,
}

TAG_RE = re.compile(r"<[^>]+>")


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
class CoverageRow:
    id: str
    rfc: str
    check_class: str
    class_label: str
    rfc_section: str
    source_refs: list[SourceRef]
    evidence_statement: str
    denominator_line: int
    status: str = "Unknown"
    maude_evidence: list[str] = field(default_factory=list)
    assessment: str = ""
    numerator_line: int | None = None
    matched_lines: int = 0
    unmatched_lines: list[dict[str, Any]] = field(default_factory=list)

    def status_slug(self) -> str:
        return self.status.lower().replace(" ", "-")

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rfc": self.rfc,
            "class": self.check_class,
            "classLabel": self.class_label,
            "rfcSection": self.rfc_section,
            "sourceRefs": [ref.to_json() for ref in self.source_refs],
            "status": self.status,
            "statusSlug": self.status_slug(),
            "maudeRefs": self.maude_evidence,
            "denominatorLine": self.denominator_line,
            "numeratorLine": self.numerator_line,
            "match": {
                "matchedLines": self.matched_lines,
                "unmatchedLines": self.unmatched_lines,
            },
        }


def split_md_row(line: str) -> list[str]:
    """Split a Markdown table row while respecting inline-code spans."""
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]

    cells: list[str] = []
    current: list[str] = []
    in_code = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "`":
            in_code = not in_code
            current.append(ch)
        elif ch == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    cells.append("".join(current).strip())
    return cells


def strip_inline_code(value: str) -> str:
    value = value.strip()
    if value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value


def normalize_status(value: str) -> str:
    normalized = re.sub(r"\s+", " ", strip_inline_code(value)).strip().lower()
    if normalized == "implemented":
        return "Implemented"
    if normalized == "partial":
        return "Partial"
    if normalized == "not implemented":
        return "Not implemented"
    return strip_inline_code(value).strip()


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
            raise ValueError(f"Cannot parse source ref {token!r} in RFC {rfc}")

        expected = f"rfc{rfc}.txt"
        if file_name != expected:
            raise ValueError(f"Source ref {token!r} disagrees with RFC column {rfc}")
        if end < start:
            raise ValueError(f"Invalid descending source ref {token!r}")
        refs.append(SourceRef(raw=token, file=file_name, start=start, end=end))
    return refs


def class_from_id(row_id: str) -> tuple[str, str]:
    parts = row_id.split("-")
    if len(parts) < 3:
        raise ValueError(f"Unexpected row ID {row_id}")
    prefix = parts[1]
    if prefix not in CLASS_BY_PREFIX:
        raise ValueError(f"Unknown row class prefix {prefix} in {row_id}")
    return CLASS_BY_PREFIX[prefix]


def parse_denominator(path: Path) -> dict[str, CoverageRow]:
    rows: dict[str, CoverageRow] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not re.match(r"^\|\s*`\d{4}-[A-Z]+-\d+`\s*\|", line):
            continue
        cells = split_md_row(line)
        if len(cells) < 5:
            raise ValueError(f"Malformed denominator row at {path}:{line_no}")

        row_id = strip_inline_code(cells[0])
        rfc = cells[1].strip()
        check_class, class_label = class_from_id(row_id)
        row = CoverageRow(
            id=row_id,
            rfc=rfc,
            check_class=check_class,
            class_label=class_label,
            rfc_section=cells[2].strip(),
            source_refs=parse_source_refs(cells[3], rfc),
            evidence_statement=cells[4].strip(),
            denominator_line=line_no,
        )
        if row_id in rows:
            raise ValueError(f"Duplicate denominator row {row_id}")
        rows[row_id] = row
    return rows


def parse_numerator(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not re.match(r"^\|\s*`\d{4}-[A-Z]+-\d+`\s*\|", line):
            continue
        cells = split_md_row(line)
        if len(cells) < 4:
            raise ValueError(f"Malformed numerator row at {path}:{line_no}")

        row_id = strip_inline_code(cells[0])
        status = normalize_status(cells[1])
        maude_evidence = re.findall(r"`([^`]+)`", cells[2])
        rows[row_id] = {
            "status": status,
            "maudeEvidence": maude_evidence,
            "assessment": cells[3].strip(),
            "line": line_no,
        }
    return rows


def join_rows(denominator: dict[str, CoverageRow], numerator: dict[str, dict[str, Any]]) -> list[CoverageRow]:
    missing_num = sorted(set(denominator) - set(numerator))
    extra_num = sorted(set(numerator) - set(denominator))
    if missing_num or extra_num:
        raise ValueError(f"Numerator/denominator ID mismatch: missing={missing_num}, extra={extra_num}")

    joined = []
    for row_id in sorted(denominator):
        row = denominator[row_id]
        num = numerator[row_id]
        row.status = num["status"]
        row.maude_evidence = num["maudeEvidence"]
        row.assessment = num["assessment"]
        row.numerator_line = num["line"]
        joined.append(row)
    return joined


def read_spec_lines() -> dict[str, list[str]]:
    specs: dict[str, list[str]] = {}
    for name in ("rfc5246.txt", "rfc8446.txt"):
        path = SPEC_DIR / name
        # RFC text citations in denominator-v1.md are newline-counted.  Do not
        # use splitlines(), because it treats form-feed page breaks as new lines
        # and shifts RFC line numbers.
        specs[name] = path.read_text(encoding="utf-8", errors="replace").split("\n")
    return specs


def line_groups_for_rfc(rows: list[CoverageRow], specs: dict[str, list[str]], rfc: str) -> dict[int, dict[str, Any]]:
    groups: dict[int, dict[str, Any]] = {}
    for row in rows:
        if row.rfc != rfc:
            continue
        for ref in row.source_refs:
            spec_lines = specs[ref.file]
            if ref.end > len(spec_lines):
                raise ValueError(f"{row.id} cites {ref.file}:{ref.start}-{ref.end}, beyond {len(spec_lines)} lines")
            for line_no in range(ref.start, ref.end + 1):
                groups.setdefault(line_no, {"ids": [], "text": spec_lines[line_no - 1]})
                if row.id not in groups[line_no]["ids"]:
                    groups[line_no]["ids"].append(row.id)
    return groups


def strongest_status(statuses: list[str]) -> str:
    if len(set(statuses)) > 1:
        return "mixed"
    return statuses[0].lower().replace(" ", "-")


def common_class(classes: list[str]) -> str:
    return classes[0] if len(set(classes)) == 1 else "mixed"


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


def annotate_rfc_html(rows: list[CoverageRow], specs: dict[str, list[str]], rfc: str) -> tuple[str, dict[str, Any]]:
    raw_path = RAW_DIR / f"rfc{rfc}.html"
    html_text = raw_path.read_text(encoding="utf-8", errors="replace")

    start = html_text.find('<div class="rfcmarkup">')
    end = html_text.find("</div>", start)
    if start == -1 or end == -1:
        raise ValueError(f"Could not locate rfcmarkup content in {raw_path}")

    content_start = start
    content_end = end
    content = html_text[content_start:content_end]

    row_by_id = {row.id: row for row in rows}
    line_groups = line_groups_for_rfc(rows, specs, rfc)
    html_lines = content.split("\n")
    rendered_lines = [rendered_html_line(line) for line in html_lines]
    search_pos = 0
    used_html_indices: set[int] = set()
    matched_lines = 0
    unmatched: list[dict[str, Any]] = []

    for line_no in sorted(line_groups):
        group = line_groups[line_no]
        text = group["text"].rstrip("\r\n")
        ids = sorted(group["ids"])
        if not text.strip():
            continue

        idx, match_method = find_rendered_line_for_source(
            rendered_lines=rendered_lines,
            html_lines=html_lines,
            spec_lines=specs[f"rfc{rfc}.txt"],
            source_line_no=line_no,
            search_pos=search_pos,
            used_html_indices=used_html_indices,
        )

        if idx == -1:
            for row_id in ids:
                row_by_id[row_id].unmatched_lines.append({"line": line_no, "text": text})
            unmatched.append({"line": line_no, "ids": ids, "text": text})
            continue

        statuses = [row_by_id[row_id].status for row_id in ids]
        classes = [row_by_id[row_id].check_class for row_id in ids]
        status_slug = strongest_status(statuses)
        class_slug = common_class(classes)
        attrs = {
            "class": f"rfcov status-{status_slug} cat-{class_slug}",
            "data-rfcov-ids": ",".join(ids),
            "data-rfcov-status": status_slug,
            "data-rfcov-class": class_slug,
            "data-rfcov-line": str(line_no),
            "data-rfcov-match": match_method,
            "tabindex": "0",
        }
        attr_text = " ".join(f'{key}="{html.escape(value, quote=True)}"' for key, value in attrs.items())
        html_lines[idx] = f"<span {attr_text}>{html_lines[idx]}</span>"
        rendered_lines[idx] = rendered_html_line(html_lines[idx])
        used_html_indices.add(idx)
        search_pos = idx + 1
        matched_lines += 1
        for row_id in ids:
            row_by_id[row_id].matched_lines += 1

    content = "\n".join(html_lines)
    data = {
        "schema": "rfc-check-coverage-viewer-v1",
        "rfc": rfc,
        "source": {
            "html": f"https://datatracker.ietf.org/doc/html/rfc{rfc}",
            "rawPath": str(raw_path.relative_to(ROOT)),
        },
        "summary": summarize_rows([row for row in rows if row.rfc == rfc]),
        "matchSummary": {
            "matchedLines": matched_lines,
            "unmatchedLines": len(unmatched),
            "citedNonBlankLines": matched_lines + len(unmatched),
        },
        "rows": [row.to_json() for row in rows if row.rfc == rfc],
    }

    annotated = html_text[:content_start] + content + html_text[content_end:]
    annotated = inject_assets(annotated, rfc, data)
    return annotated, {"rfc": rfc, "unmatched": unmatched, "data": data}


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


def context_match_score(
    rendered_lines: list[str],
    spec_lines: list[str],
    source_line_no: int,
    html_idx: int,
    window: int = 8,
) -> int:
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


def summarize_rows(rows: list[CoverageRow]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "totalRows": len(rows),
        "byStatus": {},
        "byClass": {},
    }
    for row in rows:
        summary["byStatus"][row.status] = summary["byStatus"].get(row.status, 0) + 1
        class_bucket = summary["byClass"].setdefault(row.check_class, {"total": 0, "byStatus": {}})
        class_bucket["total"] += 1
        class_bucket["byStatus"][row.status] = class_bucket["byStatus"].get(row.status, 0) + 1
    return summary


def inject_assets(html_text: str, rfc: str, data: dict[str, Any]) -> str:
    css_tag = '<link rel="stylesheet" href="rfc-coverage.css">\n'
    if "rfc-coverage.css" not in html_text:
        html_text = html_text.replace("</head>", f"{css_tag}</head>", 1)

    data_json = (
        json.dumps(data, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
    )
    script_tags = (
        f'<script id="rfcov-data" type="application/json" data-rfc="{rfc}">{data_json}</script>\n'
        '<script src="rfc-coverage.js"></script>\n'
    )
    html_text = re.sub(r"<script>\(function\(\).*?</script></body>", "</body>", html_text, flags=re.S)
    if "rfc-coverage.js" not in html_text:
        html_text = html_text.replace("</body>", f"{script_tags}</body>", 1)
    return html_text


def write_coverage_data(rows: list[CoverageRow], per_rfc: list[dict[str, Any]]) -> None:
    data = {
        "schema": "rfc-check-coverage-manifest-v1",
        "summary": summarize_rows(rows),
        "rfcs": {item["rfc"]: item["data"]["matchSummary"] for item in per_rfc},
        "rows": [row.to_json() for row in rows],
    }
    (VIEWER_DIR / "coverage-data.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_unmatched_report(per_rfc: list[dict[str, Any]]) -> None:
    lines = [
        "# RFC Coverage Viewer Unmatched Report",
        "",
        "This report lists cited RFC text lines that were not wrapped in the downloaded datatracker HTML.",
        "Most remaining entries are section headings or page headers that are deliberately left unwrapped to avoid changing the datatracker document structure.",
        "",
    ]
    for item in per_rfc:
        rfc = item["rfc"]
        unmatched = item["unmatched"]
        data = item["data"]
        summary = data["matchSummary"]
        lines.extend([
            f"## RFC {rfc}",
            "",
            f"- Matched cited nonblank lines: {summary['matchedLines']}",
            f"- Unmatched cited nonblank lines: {summary['unmatchedLines']}",
            "",
        ])
        if not unmatched:
            lines.append("No unmatched cited lines.")
            lines.append("")
            continue
        for entry in unmatched:
            ids = ", ".join(f"`{row_id}`" for row_id in entry["ids"])
            lines.append(f"- line {entry['line']}: {ids}")
        lines.append("")
    (VIEWER_DIR / "unmatched-report.md").write_text("\n".join(lines), encoding="utf-8")


def write_index(per_rfc: list[dict[str, Any]]) -> None:
    cards = []
    for item in per_rfc:
        rfc = item["rfc"]
        summary = item["data"]["matchSummary"]
        cards.append(
            f'<a class="rfcov-index-card" href="rfc{rfc}-coverage.html">'
            f"<strong>RFC {rfc}</strong>"
            f"<span>{summary['matchedLines']} matched / {summary['unmatchedLines']} unmatched cited lines</span>"
            "</a>"
        )

    index = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RFC-check Coverage Viewer</title>
  <link rel="stylesheet" href="rfc-coverage.css">
</head>
<body class="rfcov-index">
  <main>
    <h1>RFC-check Coverage Viewer</h1>
    <p>Annotated datatracker RFC HTML pages generated from denominator-v1.md and numerator-v1.md.</p>
    <div class="rfcov-index-grid">
      {''.join(cards)}
    </div>
    <p><a href="unmatched-report.md">Unmatched report</a> · <a href="coverage-data.json">Coverage data</a></p>
  </main>
</body>
</html>
"""
    (VIEWER_DIR / "index.html").write_text(index, encoding="utf-8")


def validate_counts(rows: list[CoverageRow]) -> None:
    if len(rows) != 168:
        raise ValueError(f"Expected 168 coverage rows, got {len(rows)}")
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    expected = {"Implemented": 90, "Partial": 52, "Not implemented": 26}
    if counts != expected:
        raise ValueError(f"Unexpected status counts: {counts}; expected {expected}")


def build() -> None:
    denominator = parse_denominator(DENOMINATOR)
    numerator = parse_numerator(NUMERATOR)
    rows = join_rows(denominator, numerator)
    validate_counts(rows)

    specs = read_spec_lines()
    per_rfc = []
    for rfc in ("5246", "8446"):
        annotated, result = annotate_rfc_html(rows, specs, rfc)
        (VIEWER_DIR / f"rfc{rfc}-coverage.html").write_text(annotated, encoding="utf-8")
        per_rfc.append(result)

    write_coverage_data(rows, per_rfc)
    write_unmatched_report(per_rfc)
    write_index(per_rfc)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    build()


if __name__ == "__main__":
    main()
