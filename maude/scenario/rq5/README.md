# RQ5 aggregate behavior-deviation experiments

This directory tests coarse scenario properties that ask whether any generated RFC behavior deviation eventually reaches an error state.

The generated aggregate module defines:

- `allBehaviorDeviationSetV2`: all non-empty `behaviorDeviationSpecificationN` entries extracted from `rfc/5246-core.maude`, relabeled as `'allBehaviorDeviationSetV2`.
- `allBehaviorDeviationSetV3`: all non-empty entries extracted from `rfc/8446-core.maude`, `rfc/hrr.maude`, and `rfc/psk.maude`, relabeled as `'allBehaviorDeviationSetV3`.

The common properties are:

```maude
(anyStep *) ; ruleLabel('allBehaviorDeviationSetV2) ; (anyStep *) ;
((N1 . CI . @clientState = av[V2C-ERROR]) or
 (N2 . SI . @serverState = av[V2S-ERROR]))

(anyStep *) ; ruleLabel('allBehaviorDeviationSetV3) ; (anyStep *) ;
((N1 . CI . @clientState = av[V3C-ERROR]) or
 (N2 . SI . @serverState = av[V3S-ERROR]))
```

Regenerate the aggregate after editing `maude/scenario/rfc/*.maude`:

```sh
python3 maude/scenario/rq5/scripts/generate_aggregate.py
```

Smoke test:

```sh
cd maude/scenario/rq5
../../maude/maude-3.5.1/maude -no-advise smoke.maude
```

Count examples use a cap. If the result equals the cap, raise the cap to decide whether more solutions exist.

```maude
red rq5CountUpTo(TLS-12, initialCWA, rq5Tls12Conf,
                 allBehaviorDeviationSetV2,
                 allBehaviorDeviationScenarioPropertyV2,
                 0, 10) .

red rq5CountUpTo(TLS-13, initialCWA, rq5Tls13CoreConf,
                 allBehaviorDeviationSetV3,
                 allBehaviorDeviationScenarioPropertyV3,
                 0, 10) .

red rq5CountUpTo(TLS-13, initialCWA, rq5Tls13HrrConf,
                 allBehaviorDeviationSetV3,
                 allBehaviorDeviationScenarioPropertyV3,
                 0, 10) .

red rq5CountUpTo(TLS-13, initialCWA, rq5Tls13PskDheConf,
                 allBehaviorDeviationSetV3,
                 allBehaviorDeviationScenarioPropertyV3,
                 0, 10) .

red rq5CountUpTo(TLS-13, initialCWA, rq5Tls13PskDheHrrConf,
                 allBehaviorDeviationSetV3,
                 allBehaviorDeviationScenarioPropertyV3,
                 0, 10) .

red rq5CountUpTo(TLS-13, initialCWA, rq5Tls13PskKeConf,
                 allBehaviorDeviationSetV3,
                 allBehaviorDeviationScenarioPropertyV3,
                 0, 10) .
```

Use `tls13-core.maude`, `tls13-hrr.maude`, and `tls13-psk.maude` because the V3 aggregate covers RFC 8446 core, HRR, and PSK specs, but those paths require different initial configurations.
