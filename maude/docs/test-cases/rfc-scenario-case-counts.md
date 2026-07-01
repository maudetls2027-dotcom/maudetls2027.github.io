# RFC Scenario Test-Case Counts

Generated from `maude/scenario/rfc/` on 2026-06-27.

Pattern classification for these same active scenarios is recorded in
`maude/docs/test-cases/rfc-scenario-pattern-classification.md`.

## Counting Basis

- A `scenN` row is included when an active `scenarioPropertyN` exists.
- `Deviation entries` is the number of active `BehaviorDVSpec` tuples in `behaviorDeviationSpecificationN`.
- `empty` behavior deviation specifications count as `0` deviation entries but remain active scenario/property checks.
- Commented-out definitions are excluded. This matters for `5246-core` `scen6`/`scen8`.

## Summary

| Source | Active scenario properties | Active behaviorDeviationSpecification ops | Non-empty behaviorDeviationSpecification ops | Deviation entries |
|---|---:|---:|---:|---:|
| `5246-core.maude` | 50 | 49 | 45 | 389 |
| `8446-core.maude` | 93 | 93 | 93 | 728 |
| `hrr.maude` | 64 | 64 | 64 | 506 |
| `psk.maude` | 141 | 141 | 141 | 1198 |
| **Total** | **348** | **347** | **343** | **2821** |

## File Notes

- `5246-core.maude`: `scenarioProperty6` is active, but `behaviorDeviationSpecification6` is commented out, so `scen6` has no active deviation spec. `scen8` is fully commented out and is not counted. `scen40`, `scen41`, `scen43`, and `scen50` use `empty` deviation specs.
- `8446-core.maude`, `hrr.maude`, and `psk.maude`: every active `scenarioPropertyN` has an active non-empty `behaviorDeviationSpecificationN`.

## Additional P1/P3/P4/P5 Scenarios

Additional disallowed-extension, field-replacement, message-omission, and
required-content-empty scenarios are recorded separately under
`maude/scenario/rfc-additional/`. They are not included in the original
`maude/scenario/rfc/` totals above.

| Source | Active scenario properties | Active behaviorDeviationSpecification ops | Non-empty behaviorDeviationSpecification ops | Deviation entries |
|---|---:|---:|---:|---:|
| `rfc-additional/5246-core.maude` | 13 | 13 | 13 | 564 |
| `rfc-additional/8446-core.maude` | 4 | 4 | 4 | 4 |
| `rfc-additional/hrr.maude` | 5 | 5 | 5 | 5 |
| `rfc-additional/8446.maude` | 10 | 10 | 10 | 10 |
| **Additional total** | **32** | **32** | **32** | **583** |

- Additional P1 entries: `5246-core` `scen9` generates all ordered two-entry `signature_algorithms` lists with repetition allowed for `ServerHelloV2`, giving `16 x 16 = 256` deviation entries.
- Additional P3 entries: `5246-core` `scen10`-`scen13` add 300 `setM(...)` deviations: 100 two-entry `signature_algorithms` lists and 200 two-entry `cipherSuites` lists.
- Additional P5 entries are single `skip()` deviations: `5246-core` `scen1`-`scen6`, `8446-core` `scen1`-`scen3`, `hrr` `scen1`-`scen2`, and `8446` `scen1`-`scen3`.
- Additional P4 entries are single `setM(...)` deviations that keep the field or extension present while replacing required content with an empty list: `5246-core` `scen7`-`scen8`, `8446-core` `scen4`, `hrr` `scen3`-`scen5`, and `8446` `scen4`-`scen10`.
- `rfc-additional/hrr.maude` `scen2` is run with `initConfClientAuth`; `scen1` and `scen3`-`scen5` are run with `initConf`.
- `rfc-additional/8446.maude` records PSK/resumption additions: `scen1`, `scen4`, and `scen6` with `initConf-psk-dhe`; `scen2` and `scen5` with `initConf-psk-ke`; `scen3` and `scen7`-`scen10` with `initConf-psk-dhe-hrr`.

## `5246-core.maude`

| Scen | Deviation entries | Scenario property | Notes |
|---|---:|---|---|
| `scen1` | 12 | yes | - |
| `scen2` | 3 | yes | - |
| `scen3` | 1 | yes | - |
| `scen4` | 82 | yes | - |
| `scen5` | 1 | yes | - |
| `scen6` | 0 | yes | no active `behaviorDeviationSpecification6` |
| `scen7` | 16 | yes | - |
| `scen9` | 13 | yes | - |
| `scen10` | 2 | yes | - |
| `scen11` | 1 | yes | - |
| `scen12` | 1 | yes | - |
| `scen13` | 12 | yes | - |
| `scen14` | 3 | yes | - |
| `scen15` | 1 | yes | - |
| `scen16` | 12 | yes | - |
| `scen17` | 3 | yes | - |
| `scen18` | 16 | yes | - |
| `scen19` | 1 | yes | - |
| `scen20` | 12 | yes | - |
| `scen21` | 3 | yes | - |
| `scen22` | 3 | yes | - |
| `scen23` | 83 | yes | - |
| `scen24` | 2 | yes | - |
| `scen25` | 3 | yes | - |
| `scen26` | 16 | yes | - |
| `scen27` | 16 | yes | - |
| `scen28` | 2 | yes | - |
| `scen29` | 1 | yes | - |
| `scen30` | 1 | yes | - |
| `scen31` | 1 | yes | - |
| `scen32` | 12 | yes | - |
| `scen33` | 12 | yes | - |
| `scen34` | 3 | yes | - |
| `scen35` | 1 | yes | - |
| `scen36` | 12 | yes | - |
| `scen37` | 3 | yes | - |
| `scen38` | 12 | yes | - |
| `scen39` | 3 | yes | - |
| `scen40` | 0 | yes | `empty` spec |
| `scen41` | 0 | yes | `empty` spec |
| `scen42` | 1 | yes | - |
| `scen43` | 0 | yes | `empty` spec |
| `scen44` | 1 | yes | - |
| `scen45` | 1 | yes | - |
| `scen46` | 1 | yes | - |
| `scen47` | 1 | yes | - |
| `scen48` | 1 | yes | - |
| `scen49` | 1 | yes | - |
| `scen50` | 0 | yes | `empty` spec |
| `scen51` | 1 | yes | - |

## `8446-core.maude`

| Scen | Deviation entries | Scenario property | Notes |
|---|---:|---|---|
| `scen1` | 3 | yes | - |
| `scen2` | 2 | yes | - |
| `scen3` | 85 | yes | - |
| `scen4` | 16 | yes | - |
| `scen5` | 1 | yes | - |
| `scen6` | 1 | yes | - |
| `scen7` | 1 | yes | - |
| `scen8` | 16 | yes | - |
| `scen9` | 16 | yes | - |
| `scen10` | 13 | yes | - |
| `scen11` | 1 | yes | - |
| `scen12` | 16 | yes | - |
| `scen13` | 1 | yes | - |
| `scen14` | 1 | yes | - |
| `scen15` | 5 | yes | - |
| `scen16` | 5 | yes | - |
| `scen17` | 5 | yes | - |
| `scen18` | 5 | yes | - |
| `scen19` | 5 | yes | - |
| `scen20` | 5 | yes | - |
| `scen21` | 5 | yes | - |
| `scen22` | 5 | yes | - |
| `scen23` | 5 | yes | - |
| `scen24` | 5 | yes | - |
| `scen25` | 5 | yes | - |
| `scen26` | 5 | yes | - |
| `scen27` | 5 | yes | - |
| `scen28` | 13 | yes | - |
| `scen29` | 4 | yes | - |
| `scen30` | 13 | yes | - |
| `scen31` | 4 | yes | - |
| `scen32` | 13 | yes | - |
| `scen33` | 4 | yes | - |
| `scen34` | 13 | yes | - |
| `scen35` | 4 | yes | - |
| `scen36` | 13 | yes | - |
| `scen37` | 85 | yes | - |
| `scen38` | 3 | yes | - |
| `scen39` | 1 | yes | - |
| `scen40` | 16 | yes | - |
| `scen41` | 16 | yes | - |
| `scen42` | 2 | yes | - |
| `scen43` | 1 | yes | - |
| `scen44` | 1 | yes | - |
| `scen45` | 3 | yes | - |
| `scen46` | 13 | yes | - |
| `scen47` | 1 | yes | - |
| `scen48` | 1 | yes | - |
| `scen49` | 3 | yes | - |
| `scen50` | 13 | yes | - |
| `scen51` | 3 | yes | - |
| `scen52` | 16 | yes | - |
| `scen53` | 2 | yes | - |
| `scen54` | 1 | yes | - |
| `scen55` | 3 | yes | - |
| `scen56` | 1 | yes | - |
| `scen57` | 1 | yes | - |
| `scen58` | 16 | yes | - |
| `scen59` | 3 | yes | - |
| `scen60` | 16 | yes | - |
| `scen61` | 2 | yes | - |
| `scen62` | 1 | yes | - |
| `scen63` | 1 | yes | - |
| `scen64` | 1 | yes | - |
| `scen65` | 16 | yes | - |
| `scen66` | 1 | yes | - |
| `scen67` | 1 | yes | - |
| `scen68` | 5 | yes | - |
| `scen69` | 5 | yes | - |
| `scen70` | 5 | yes | - |
| `scen71` | 5 | yes | - |
| `scen72` | 5 | yes | - |
| `scen73` | 5 | yes | - |
| `scen74` | 5 | yes | - |
| `scen75` | 5 | yes | - |
| `scen76` | 5 | yes | - |
| `scen77` | 5 | yes | - |
| `scen78` | 5 | yes | - |
| `scen79` | 5 | yes | - |
| `scen80` | 5 | yes | - |
| `scen81` | 5 | yes | - |
| `scen82` | 5 | yes | - |
| `scen83` | 5 | yes | - |
| `scen84` | 13 | yes | - |
| `scen85` | 4 | yes | - |
| `scen86` | 13 | yes | - |
| `scen87` | 4 | yes | - |
| `scen88` | 13 | yes | - |
| `scen89` | 4 | yes | - |
| `scen90` | 13 | yes | - |
| `scen91` | 4 | yes | - |
| `scen92` | 13 | yes | - |
| `scen93` | 4 | yes | - |

## `hrr.maude`

| Scen | Deviation entries | Scenario property | Notes |
|---|---:|---|---|
| `scen1` | 16 | yes | - |
| `scen2` | 16 | yes | - |
| `scen3` | 2 | yes | - |
| `scen4` | 1 | yes | - |
| `scen5` | 1 | yes | - |
| `scen6` | 1 | yes | - |
| `scen7` | 1 | yes | - |
| `scen8` | 1 | yes | - |
| `scen9` | 3 | yes | - |
| `scen10` | 16 | yes | - |
| `scen11` | 85 | yes | - |
| `scen12` | 3 | yes | - |
| `scen13` | 2 | yes | - |
| `scen14` | 3 | yes | - |
| `scen15` | 16 | yes | - |
| `scen16` | 5 | yes | - |
| `scen17` | 5 | yes | - |
| `scen18` | 5 | yes | - |
| `scen19` | 5 | yes | - |
| `scen20` | 5 | yes | - |
| `scen21` | 16 | yes | - |
| `scen22` | 3 | yes | - |
| `scen23` | 2 | yes | - |
| `scen24` | 1 | yes | - |
| `scen25` | 1 | yes | - |
| `scen26` | 1 | yes | - |
| `scen27` | 1 | yes | - |
| `scen28` | 1 | yes | - |
| `scen29` | 1 | yes | - |
| `scen30` | 1 | yes | - |
| `scen31` | 1 | yes | - |
| `scen32` | 16 | yes | - |
| `scen33` | 16 | yes | - |
| `scen34` | 3 | yes | - |
| `scen35` | 13 | yes | - |
| `scen36` | 5 | yes | - |
| `scen37` | 5 | yes | - |
| `scen38` | 5 | yes | - |
| `scen39` | 5 | yes | - |
| `scen40` | 5 | yes | - |
| `scen41` | 5 | yes | - |
| `scen42` | 13 | yes | - |
| `scen43` | 4 | yes | - |
| `scen44` | 16 | yes | - |
| `scen45` | 16 | yes | - |
| `scen46` | 2 | yes | - |
| `scen47` | 1 | yes | - |
| `scen48` | 1 | yes | - |
| `scen49` | 1 | yes | - |
| `scen50` | 1 | yes | - |
| `scen51` | 1 | yes | - |
| `scen52` | 3 | yes | - |
| `scen53` | 13 | yes | - |
| `scen54` | 85 | yes | - |
| `scen55` | 3 | yes | - |
| `scen56` | 2 | yes | - |
| `scen57` | 3 | yes | - |
| `scen58` | 5 | yes | - |
| `scen59` | 5 | yes | - |
| `scen60` | 5 | yes | - |
| `scen61` | 5 | yes | - |
| `scen62` | 5 | yes | - |
| `scen63` | 13 | yes | - |
| `scen64` | 4 | yes | - |

## `psk.maude`

| Scen | Deviation entries | Scenario property | Notes |
|---|---:|---|---|
| `scen1` | 1 | yes | - |
| `scen2` | 1 | yes | - |
| `scen3` | 1 | yes | - |
| `scen4` | 1 | yes | - |
| `scen5` | 2 | yes | - |
| `scen6` | 13 | yes | - |
| `scen7` | 16 | yes | - |
| `scen8` | 3 | yes | - |
| `scen9` | 16 | yes | - |
| `scen10` | 3 | yes | - |
| `scen11` | 1 | yes | - |
| `scen12` | 85 | yes | - |
| `scen13` | 3 | yes | - |
| `scen14` | 2 | yes | - |
| `scen15` | 1 | yes | - |
| `scen16` | 1 | yes | - |
| `scen17` | 3 | yes | - |
| `scen18` | 16 | yes | - |
| `scen19` | 16 | yes | - |
| `scen20` | 85 | yes | - |
| `scen21` | 3 | yes | - |
| `scen22` | 2 | yes | - |
| `scen23` | 16 | yes | - |
| `scen24` | 16 | yes | - |
| `scen25` | 2 | yes | - |
| `scen26` | 1 | yes | - |
| `scen27` | 1 | yes | - |
| `scen28` | 1 | yes | - |
| `scen29` | 1 | yes | - |
| `scen30` | 1 | yes | - |
| `scen31` | 1 | yes | - |
| `scen32` | 1 | yes | - |
| `scen33` | 1 | yes | - |
| `scen34` | 2 | yes | - |
| `scen35` | 13 | yes | - |
| `scen36` | 16 | yes | - |
| `scen37` | 3 | yes | - |
| `scen38` | 16 | yes | - |
| `scen39` | 2 | yes | - |
| `scen40` | 2 | yes | - |
| `scen41` | 85 | yes | - |
| `scen42` | 3 | yes | - |
| `scen43` | 2 | yes | - |
| `scen44` | 1 | yes | - |
| `scen45` | 1 | yes | - |
| `scen46` | 3 | yes | - |
| `scen47` | 13 | yes | - |
| `scen48` | 13 | yes | - |
| `scen49` | 85 | yes | - |
| `scen50` | 3 | yes | - |
| `scen51` | 2 | yes | - |
| `scen52` | 16 | yes | - |
| `scen53` | 16 | yes | - |
| `scen54` | 2 | yes | - |
| `scen55` | 1 | yes | - |
| `scen56` | 1 | yes | - |
| `scen57` | 3 | yes | - |
| `scen58` | 16 | yes | - |
| `scen59` | 2 | yes | - |
| `scen60` | 1 | yes | - |
| `scen61` | 1 | yes | - |
| `scen62` | 5 | yes | - |
| `scen63` | 5 | yes | - |
| `scen64` | 5 | yes | - |
| `scen65` | 5 | yes | - |
| `scen66` | 5 | yes | - |
| `scen67` | 5 | yes | - |
| `scen68` | 5 | yes | - |
| `scen69` | 5 | yes | - |
| `scen70` | 5 | yes | - |
| `scen71` | 5 | yes | - |
| `scen72` | 5 | yes | - |
| `scen73` | 5 | yes | - |
| `scen74` | 5 | yes | - |
| `scen75` | 5 | yes | - |
| `scen76` | 5 | yes | - |
| `scen77` | 5 | yes | - |
| `scen78` | 5 | yes | - |
| `scen79` | 5 | yes | - |
| `scen80` | 5 | yes | - |
| `scen81` | 5 | yes | - |
| `scen82` | 5 | yes | - |
| `scen83` | 5 | yes | - |
| `scen84` | 5 | yes | - |
| `scen85` | 5 | yes | - |
| `scen86` | 5 | yes | - |
| `scen87` | 5 | yes | - |
| `scen88` | 5 | yes | - |
| `scen89` | 5 | yes | - |
| `scen90` | 5 | yes | - |
| `scen91` | 5 | yes | - |
| `scen92` | 5 | yes | - |
| `scen93` | 5 | yes | - |
| `scen94` | 5 | yes | - |
| `scen95` | 5 | yes | - |
| `scen96` | 85 | yes | - |
| `scen97` | 3 | yes | - |
| `scen98` | 2 | yes | - |
| `scen99` | 1 | yes | - |
| `scen100` | 1 | yes | - |
| `scen101` | 3 | yes | - |
| `scen102` | 2 | yes | - |
| `scen103` | 13 | yes | - |
| `scen104` | 1 | yes | - |
| `scen105` | 1 | yes | - |
| `scen106` | 3 | yes | - |
| `scen107` | 1 | yes | - |
| `scen108` | 1 | yes | - |
| `scen109` | 1 | yes | - |
| `scen110` | 13 | yes | - |
| `scen111` | 16 | yes | - |
| `scen112` | 2 | yes | - |
| `scen113` | 1 | yes | - |
| `scen114` | 1 | yes | - |
| `scen115` | 85 | yes | - |
| `scen116` | 3 | yes | - |
| `scen117` | 3 | yes | - |
| `scen118` | 16 | yes | - |
| `scen119` | 2 | yes | - |
| `scen120` | 1 | yes | - |
| `scen121` | 5 | yes | - |
| `scen122` | 5 | yes | - |
| `scen123` | 5 | yes | - |
| `scen124` | 5 | yes | - |
| `scen125` | 5 | yes | - |
| `scen126` | 5 | yes | - |
| `scen127` | 5 | yes | - |
| `scen128` | 5 | yes | - |
| `scen129` | 5 | yes | - |
| `scen130` | 5 | yes | - |
| `scen131` | 5 | yes | - |
| `scen132` | 5 | yes | - |
| `scen133` | 5 | yes | - |
| `scen134` | 5 | yes | - |
| `scen135` | 5 | yes | - |
| `scen136` | 13 | yes | - |
| `scen137` | 4 | yes | - |
| `scen138` | 13 | yes | - |
| `scen139` | 4 | yes | - |
| `scen140` | 13 | yes | - |
| `scen141` | 4 | yes | - |
