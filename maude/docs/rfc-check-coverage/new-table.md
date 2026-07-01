# RFC-Check Coverage Table

This table uses compact buckets derived from official RFC section ranges.
Covered/uncovered counts include only included MUST/MUST NOT statements;
excluded candidates are omitted from the denominator.

## RFC 5246

| Bucket | RFC section basis | Included | Covered | Uncovered | Coverage |
|---|---|---:|---:|---:|---:|
| Record Layer | Section 6 | 21 | 6 | 15 | 28.6% |
| Alert / ChangeCipherSpec | Sections 7.1-7.2 | 12 | 11 | 1 | 91.7% |
| Handshake: Hello / Negotiation | Sections 7.3-7.4.1 | 24 | 19 | 5 | 79.2% |
| Handshake: Server Auth / Key Exchange | Sections 7.4.2-7.4.5 | 21 | 11 | 10 | 52.4% |
| Handshake: Client Auth / Key Exchange | Sections 7.4.6-7.4.8 | 24 | 18 | 6 | 75.0% |
| Finished | Section 7.4.9 | 4 | 4 | 0 | 100.0% |
| Interoperability Requirements | Section 9, Appendix A/E | 18 | 5 | 13 | 27.8% |
| Other Sections | Other included sections | 5 | 2 | 3 | 40.0% |
| **Total** |  | **129** | **76** | **53** | **58.9%** |

## RFC 8446

| Bucket | RFC section basis | Included | Covered | Uncovered | Coverage |
|---|---|---:|---:|---:|---:|
| Protocol Overview / Key Exchange | Sections 2, 4.1 | 50 | 40 | 10 | 80.0% |
| Extensions | Section 4.2 | 96 | 71 | 25 | 74.0% |
| Server Parameters | Section 4.3 | 8 | 8 | 0 | 100.0% |
| Authentication Messages | Section 4.4 | 41 | 34 | 7 | 82.9% |
| Early Data / Post-Handshake | Sections 4.5-4.6 | 23 | 16 | 7 | 69.6% |
| Record / Alert Protocol | Sections 5-6 | 50 | 16 | 34 | 32.0% |
| Crypto / 0-RTT / Compliance | Sections 7-9 | 30 | 7 | 23 | 23.3% |
| Other Sections | Appendix B/D/E and other sections | 29 | 21 | 8 | 72.4% |
| **Total** |  | **327** | **213** | **114** | **65.1%** |

## Combined Total

| Scope | Included | Covered | Uncovered | Coverage |
|---|---:|---:|---:|---:|
| RFC 5246 | 129 | 76 | 53 | 58.9% |
| RFC 8446 | 327 | 213 | 114 | 65.1% |
| **Total** | **456** | **289** | **167** | **63.4%** |

## Notes

- RFC 5246 excluded candidates: 9.
- RFC 8446 excluded candidates: 3.
- The RFC 5246 `Finished` bucket contains the current Section 7.4.9
  included statements. The current inventory has no included Section 8
  MUST/MUST NOT statements.
