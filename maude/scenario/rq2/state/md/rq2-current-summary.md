# RQ2 Table IV Summary

Source JSONL: `maude/scenario/rq2/state/jsonl/rq2-matrix.jsonl`

Candidate time is the averaged Maude `real` time for candidate runs. Success time is reported for inspection, but Table IV uses candidate time as Exploit Test Case Generation Time.

## Table IV Draft by CVE

| CVE | Library | Version | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Success Time (s) | Status |
|---|---|---|---:|---:|---:|---:|---:|---|
| CVE-2021-3449 | OpenSSL | TLS 1.2 | 1 | 3 | 5.694 | 1 | 29.192 | failed |
| CVE-2024-5814 | wolfSSL | TLS 1.2 | 1 | 3 | 6.410 | 1 | 356.102 | failed |
| CVE-2025-12889 | wolfSSL | TLS 1.2 | 1 | 2 | 6.780 | 1 | 13.102 | failed |
| CVE-2026-25834 | Mbed TLS | TLS 1.2 | 1 | 1 | 0.499 | 1 | 0.491 | ok |
| CVE-2026-34873 | Mbed TLS | Mixed | 1 | 0 | 152.285 | 0 | 153.467 | failed |

## Version Aggregation

| Version | CVEs | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Status |
|---|---:|---:|---:|---:|---:|---|
| TLS 1.2 | 4 | 4 | 9 | 19.383 | 4 | failed |
| Mixed | 1 | 1 | 0 | 152.285 | 0 | failed |

## Bucket Breakdown

| CVE | Version | Category | Pattern | Bucket Instances | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Status |
|---|---|---|---|---:|---:|---:|---:|---|
| CVE-2021-3449 | TLS 1.2 | 5246 | P2 | 2 | 1 | 0.551 | 0 | ok |
| CVE-2021-3449 | TLS 1.2 | 5246 | P3 | 610 |  |  |  | failed |
| CVE-2021-3449 | TLS 1.2 | 5246 | P4 | 4 | 0 | 2.523 | 0 | ok |
| CVE-2021-3449 | TLS 1.2 | 5246 | P5 | 7 | 1 | 1.928 | 0 | ok |
| CVE-2024-5814 | TLS 1.2 | 5246 | P2 | 2 | 0 | 4.216 | 0 | ok |
| CVE-2024-5814 | TLS 1.2 | 5246 | P3 | 610 |  |  |  | failed |
| CVE-2024-5814 | TLS 1.2 | 5246 | P4 | 4 | 1 | 0.547 | 0 | ok |
| CVE-2024-5814 | TLS 1.2 | 5246 | P5 | 7 | 1 | 1.144 | 0 | ok |
| CVE-2025-12889 | TLS 1.2 | 5246 | P2 | 2 | 0 | 0.863 | 0 | ok |
| CVE-2025-12889 | TLS 1.2 | 5246 | P3 | 610 |  |  |  | failed |
| CVE-2025-12889 | TLS 1.2 | 5246 | P4 | 4 | 0 | 1.195 | 0 | ok |
| CVE-2025-12889 | TLS 1.2 | 5246 | P5 | 7 | 1 | 4.098 | 0 | ok |
| CVE-2026-34873 | Mixed | 8446 | P1 | 162 |  |  |  | failed |
| CVE-2026-34873 | Mixed | 8446 | P2 | 6 | 0 | 15.673 | 0 | ok |
| CVE-2026-34873 | Mixed | 8446 | P3 | 556 |  |  |  | failed |
| CVE-2026-34873 | Mixed | 8446 | P4 | 3 | 0 | 12.442 | 0 | ok |
| CVE-2026-34873 | Mixed | 8446 | P5 | 3 | 0 | 12.523 | 0 | ok |
| CVE-2026-34873 | Mixed | hrr | P1 | 157 |  |  |  | failed |
| CVE-2026-34873 | Mixed | hrr | P2 | 8 | 0 | 40.158 | 0 | ok |
| CVE-2026-34873 | Mixed | hrr | P3 | 339 |  |  |  | failed |
| CVE-2026-34873 | Mixed | hrr | P4 | 3 | 0 | 12.407 | 0 | ok |
| CVE-2026-34873 | Mixed | hrr | P5 | 2 | 0 | 12.355 | 0 | ok |
| CVE-2026-34873 | Mixed | psk | P1 | 279 |  |  |  | failed |
| CVE-2026-34873 | Mixed | psk | P3 | 897 |  |  |  | failed |
| CVE-2026-34873 | Mixed | psk | P4 | 7 | 0 | 22.208 | 0 | ok |
| CVE-2026-34873 | Mixed | psk | P5 | 3 | 0 | 12.289 | 0 | ok |
