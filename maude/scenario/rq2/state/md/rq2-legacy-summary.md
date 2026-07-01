# RQ2 Table IV Summary

Source JSONL: `maude/scenario/rq2/state/jsonl/rq2-matrix.jsonl`

Candidate time is the averaged Maude `real` time for candidate runs. Success time is reported for inspection, but Table IV uses candidate time as Exploit Test Case Generation Time.

## Table IV Draft by CVE

| CVE | Library | Version | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Success Time (s) | Status |
|---|---|---|---:|---:|---:|---:|---:|---|
| CVE-2020-24613 | wolfSSL | TLS 1.3 | 1 | 1 | 75.728 | 1 | 76.035 | ok |
| CVE-2021-3336 | wolfSSL | TLS 1.3 | 1 | 1 | 76.499 | 1 | 76.842 | ok |
| CVE-2021-3449 | OpenSSL | TLS 1.2 | 1 | 1 | 19.378 | 1 | 19.622 | ok |
| CVE-2022-25638 | wolfSSL | TLS 1.3 | 1 | 1 | 75.847 | 1 | 76.829 | ok |
| CVE-2022-25640 | wolfSSL | TLS 1.3 | 1 | 1 | 76.496 | 1 | 76.664 | ok |
| CVE-2022-39173 | wolfSSL | TLS 1.3 | 16 | 1 | 80.685 | 1 | 80.821 | ok |
| CVE-2023-3724 | wolfSSL | TLS 1.3 | 1 | 1 | 76.381 | 1 | 77.137 | ok |
| CVE-2024-5814 | wolfSSL | TLS 1.2 | 1 | 1 | 19.256 | 1 | 19.261 | ok |
| CVE-2025-11933 | wolfSSL | TLS 1.3 | 2 | 1 | 75.600 | 1 | 77.000 | ok |
| CVE-2025-11934 | wolfSSL | TLS 1.3 | 1 | 1 | 76.396 | 1 | 76.907 | ok |
| CVE-2025-11935 | wolfSSL | TLS 1.3 | 1 | 1 | 77.222 | 1 | 78.359 | ok |
| CVE-2025-11936 | wolfSSL | TLS 1.3 | 1 | 1 | 76.269 | 1 | 76.452 | ok |
| CVE-2025-12889 | wolfSSL | TLS 1.2 | 1 | 1 | 19.369 | 1 | 19.135 | ok |
| CVE-2026-25834 | Mbed TLS | TLS 1.2 | 1 | 1 | 19.047 | 1 | 19.237 | ok |
| CVE-2026-3230 | wolfSSL | TLS 1.3 | 1 | 1 | 76.559 | 1 | 77.157 | ok |

## Version Aggregation

| Version | CVEs | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Status |
|---|---:|---:|---:|---:|---:|---|
| TLS 1.2 | 4 | 4 | 4 | 77.050 | 4 | ok |
| TLS 1.3 | 11 | 27 | 11 | 843.682 | 11 | ok |
