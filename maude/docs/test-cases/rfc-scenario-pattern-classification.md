# RFC Scenario Pattern Classification

Generated from `maude/scenario/rfc/` on 2026-06-27.

## Pattern Definitions

| Pattern | Definition |
|---|---|
| P1 | Inserts a disallowed extension component. |
| P2 | Omits a required extension. |
| P3 | Replaces a modeled field value. |
| P4 | Empties required content. |
| P5 | Omits an expected message. |
| N/A | No matching P1-P5 pattern: `empty` deviation spec, no active deviation spec, or an active mutation outside the five-pattern taxonomy. |

## Classification Rules

- P4 has priority over P3 when a `setM(...)` operation empties required content, e.g. `emptyCertificateList`.
- Active `add(...)` deviations are classified as P1 only when they insert an extension component.
- `add(#cipherSuites, ...)` and `add(#compressions, ...)` are not extension-component insertions in the model semantics, so they are classified as N/A unless another pattern applies.
- Active `remove(...)` deviations are classified as P2.
- Active `setM(...)` and `setF(...)` deviations are classified as P3 unless the P4 priority rule applies.
- Active `skip()` deviations are classified as P5.
- `empty` specs, active properties without an active deviation spec, and active mutations outside P1-P5 are classified as N/A rather than forced into P1-P5.

## Scenario Summary

| Source | P1 | P2 | P3 | P4 | P5 | N/A | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| `5246-core.maude` | 12 | 2 | 27 | 2 | 1 | 6 | 50 |
| `8446-core.maude` | 22 | 6 | 62 | 2 | 0 | 1 | 93 |
| `hrr.maude` | 20 | 8 | 35 | 0 | 0 | 1 | 64 |
| `psk.maude` | 45 | 16 | 77 | 0 | 0 | 3 | 141 |
| **Total** | **99** | **32** | **201** | **4** | **1** | **11** | **348** |

## Instance Summary

These counts sum active `BehaviorDVSpec` tuples, not `scenN` rows.

| Source | P1 | P2 | P3 | P4 | P5 | N/A | Total instances |
|---|---:|---:|---:|---:|---:|---:|---:|
| `5246-core.maude` | 73 | 2 | 310 | 2 | 1 | 1 | 389 |
| `8446-core.maude` | 162 | 6 | 556 | 2 | 0 | 2 | 728 |
| `hrr.maude` | 157 | 8 | 339 | 0 | 0 | 2 | 506 |
| `psk.maude` | 279 | 16 | 897 | 0 | 0 | 6 | 1198 |
| **Total** | **671** | **32** | **2102** | **4** | **1** | **11** | **2821** |

## Additional P1/P3/P4/P5 Scenario Set

Additional scenarios under `maude/scenario/rfc-additional/` are tracked
separately from the original `maude/scenario/rfc/` corpus. They now include
P1 disallowed-extension cases, P3 field-replacement cases, P5
message-omission cases, and P4 required-content-empty cases.

| Source | P1 | P2 | P3 | P4 | P5 | N/A | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| `rfc-additional/5246-core.maude` | 1 | 0 | 4 | 2 | 6 | 0 | 13 |
| `rfc-additional/8446-core.maude` | 0 | 0 | 0 | 1 | 3 | 0 | 4 |
| `rfc-additional/hrr.maude` | 0 | 0 | 0 | 3 | 2 | 0 | 5 |
| `rfc-additional/8446.maude` | 0 | 0 | 0 | 7 | 3 | 0 | 10 |
| **Additional total** | **1** | **0** | **4** | **13** | **14** | **0** | **32** |

## Additional Instance Summary

These counts sum active `BehaviorDVSpec` tuples in
`maude/scenario/rfc-additional/`, not just `scenN` rows.

| Source | P1 | P2 | P3 | P4 | P5 | N/A | Total instances |
|---|---:|---:|---:|---:|---:|---:|---:|
| `rfc-additional/5246-core.maude` | 256 | 0 | 300 | 2 | 6 | 0 | 564 |
| `rfc-additional/8446-core.maude` | 0 | 0 | 0 | 1 | 3 | 0 | 4 |
| `rfc-additional/hrr.maude` | 0 | 0 | 0 | 3 | 2 | 0 | 5 |
| `rfc-additional/8446.maude` | 0 | 0 | 0 | 7 | 3 | 0 | 10 |
| **Additional total** | **256** | **0** | **300** | **13** | **14** | **0** | **583** |

Additional P1 scenarios:

| Source | P1 scens | Instance notes |
|---|---|---|
| `rfc-additional/5246-core.maude` | `scen9` | `16 x 16 = 256` ordered two-entry `signature_algorithms` lists on `buildServerHelloV2`, with repetition allowed |

Additional P3 scenarios:

| Source | P3 scens | Instance notes |
|---|---|---|
| `rfc-additional/5246-core.maude` | `scen10`-`scen11` | 100 two-entry `signature_algorithms` replacement lists: 31 include `{ecdsa,sha256}` and complete normally; 69 omit it and fail with `handshake-failure` |
| `rfc-additional/5246-core.maude` | `scen12`-`scen13` | 200 two-entry `cipherSuites` replacement lists: 100 include the configured common suite and complete normally; 100 omit it and fail with `handshake-failure` |

Additional P4 scenarios:

| Source | P4 scens |
|---|---|
| `rfc-additional/5246-core.maude` | `scen7`-`scen8` |
| `rfc-additional/8446-core.maude` | `scen4` |
| `rfc-additional/hrr.maude` | `scen3`-`scen5` |
| `rfc-additional/8446.maude` | `scen4`-`scen10` |

Combined with the original RFC corpus, P1 increases from `671` to `927`
behavior-deviation instances. P3 increases from `2102` to `2402` instances;
within `5246-core`, P3 increases from `310` to `610` instances. P4 increases
from `4` to `17` instances, and P5 increases from `1` to `15` instances.

## Per-Source Scenario Map

### `5246-core.maude`

| Pattern | Scens |
|---|---|
| P1 | `scen7`, `scen9`-`scen12`, `scen25`-`scen31` |
| P2 | `scen44`-`scen45` |
| P3 | `scen1`-`scen5`, `scen13`-`scen14`, `scen16`-`scen24`, `scen32`-`scen34`, `scen36`-`scen39`, `scen42`, `scen46`, `scen49`, `scen51` |
| P4 | `scen15`, `scen35` |
| P5 | `scen47` |
| N/A | `scen6`, `scen40`-`scen41`, `scen43`, `scen48`, `scen50` |

### `8446-core.maude`

| Pattern | Scens |
|---|---|
| P1 | `scen8`-`scen10`, `scen40`-`scen46`, `scen51`-`scen55`, `scen58`-`scen64` |
| P2 | `scen5`-`scen7`, `scen47`-`scen48`, `scen57` |
| P3 | `scen1`, `scen3`-`scen4`, `scen12`-`scen39`, `scen49`-`scen50`, `scen65`-`scen93` |
| P4 | `scen11`, `scen56` |
| P5 | - |
| N/A | `scen2` |

### `hrr.maude`

| Pattern | Scens |
|---|---|
| P1 | `scen1`-`scen6`, `scen9`-`scen10`, `scen32`-`scen35`, `scen44`-`scen49`, `scen52`-`scen53` |
| P2 | `scen7`-`scen8`, `scen28`-`scen31`, `scen50`-`scen51` |
| P3 | `scen11`-`scen22`, `scen24`-`scen27`, `scen36`-`scen43`, `scen54`-`scen64` |
| P4 | - |
| P5 | - |
| N/A | `scen23` |

### `psk.maude`

| Pattern | Scens |
|---|---|
| P1 | `scen5`-`scen8`, `scen17`-`scen18`, `scen23`-`scen29`, `scen34`-`scen37`, `scen46`-`scen47`, `scen52`-`scen61`, `scen101`-`scen103`, `scen106`-`scen114`, `scen117`-`scen120` |
| P2 | `scen1`-`scen4`, `scen15`-`scen16`, `scen30`-`scen33`, `scen44`-`scen45`, `scen99`-`scen100`, `scen104`-`scen105` |
| P3 | `scen9`-`scen13`, `scen19`-`scen22`, `scen38`-`scen42`, `scen48`-`scen51`, `scen62`-`scen97`, `scen115`-`scen116`, `scen121`-`scen141` |
| P4 | - |
| P5 | - |
| N/A | `scen14`, `scen43`, `scen98` |

## Notes

- `5246-core.maude` `scen6` has an active `scenarioProperty6`, but `behaviorDeviationSpecification6` is commented out, so it is N/A.
- `5246-core.maude` `scen40`, `scen41`, `scen43`, and `scen50` have active `empty` deviation specs, so they are N/A baseline/property checks.
- `5246-core.maude` `scen8` is not listed because both its deviation spec and scenario property are commented out.
- `5246-core.maude` `scen48`, `8446-core.maude` `scen2`, `hrr.maude` `scen23`, and `psk.maude` `scen14`, `scen43`, `scen98` use `add(#cipherSuites, ...)` or `add(#compressions, ...)`. Those additions target top-level message vectors, not `extensions(EXT)`, so they are active but outside P1-P5.
