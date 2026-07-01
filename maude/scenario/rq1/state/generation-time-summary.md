# RQ1 Generation-Time Summary

Source JSONL: `/home/jaehun/icse2027-2/maude/scenario/rq1/state/generation-time-matrix.jsonl`

Total Time is the sum of Maude `real` time from `set stats on`. When a job has repeated runs, its Maude time is averaged before protocol and pattern totals are summed.

## Table II Draft

| Protocol | Test Case # | Total Time (s) | Avg Time / Case (ms) | Jobs | Status |
|---|---:|---:|---:|---:|---|
| TLS 1.2 | 952 | 6736.982 | 7076.662 | 9 | failed runs: 2 |
| TLS 1.3 | 2441 | 5124.424 | 2099.313 | 27 | failed runs: 11 |

## Pattern Breakdown

| Protocol | Pattern | Test Case # | Total Time (s) | Avg Time / Case (ms) | Jobs | Status |
|---|---|---:|---:|---:|---:|---|
| TLS 1.2 | P1 | 329 | 263.452 | 800.766 | 2 | failed runs: 1 |
| TLS 1.2 | P2 | 2 | 0.421 | 210.500 | 1 | count mismatches: 1 |
| TLS 1.2 | P3 | 610 | 2064.508 | 3384.439 | 2 | failed runs: 1 |
| TLS 1.2 | P4 | 4 | 0.944 | 236.000 | 2 | ok |
| TLS 1.2 | P5 | 7 | 4407.657 | 629665.286 | 2 | ok |
| TLS 1.3 | P1 | 598 | 1010.569 | 1689.915 | 5 | failed runs: 4 |
| TLS 1.3 | P2 | 30 | 3379.164 | 112638.800 | 5 | failed runs: 2 |
| TLS 1.3 | P3 | 1792 | 0.000 | 0.000 | 5 | failed runs: 5 |
| TLS 1.3 | P4 | 13 | 710.819 | 54678.385 | 6 | count mismatches: 1 |
| TLS 1.3 | P5 | 8 | 23.872 | 2984.000 | 6 | ok |
