# RQ2 Table IV Summary

Source JSONL: `maude/scenario/rq2/state/jsonl/rq2-bucket-smoke-both.jsonl`

Candidate time is the averaged Maude `real` time for candidate runs. Success time is reported for inspection, but Table IV uses candidate time as Exploit Test Case Generation Time.

## Table IV Draft by CVE

| CVE | Library | Version | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Success Time (s) | Status |
|---|---|---|---:|---:|---:|---:|---:|---|
| CVE-2025-11935 | wolfSSL | TLS 1.3 | 1 | 2 | 1.600 | 1 | 7.751 | cap-reached |

## Version Aggregation

| Version | CVEs | Test Case Failures | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Status |
|---|---:|---:|---:|---:|---:|---|
| TLS 1.3 | 1 | 1 | 2 | 1.600 | 1 | cap-reached |

## Bucket Breakdown

| CVE | Version | Category | Pattern | Bucket Instances | Exploit Test Cases # | Generation Time (s) | Exploitability Success | Status |
|---|---|---|---|---:|---:|---:|---:|---|
| CVE-2025-11935 | TLS 1.3 | psk | P5 | 3 | 1 | 0.756 | 0 | cap-reached |
