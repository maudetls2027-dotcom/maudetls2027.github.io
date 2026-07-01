# RQ1 Generation-Time Measurement

This directory measures RFC test-case generation time for Table II.

The measurement is split by pattern because generating all P1-P5 cases in one
Maude run is too large. Each pattern-specific run aggregates the relevant
`BehaviorDVSpec` entries into one generated module and measures meta-level
solution enumeration up to one past the expected instance count:

```maude
red in <RQ1-MODULE> : rq1CountUpTo(
  <TLS-12-or-TLS-13>,
  initialCWA,
  <configuration>,
  <pattern-specific-BehaviorDVSpec-set>,
  <pattern-specific-scenario-property>,
  0,
  <expected-instance-count + 1>
) .
```

`set stats on` is enabled in every generated driver. Table II `Total Time`
should use the sum of Maude `real` time over P1-P5 jobs. The extra cap slot
checks that the next metaSrewrite solution is absent.

## Pattern Properties

Generated aggregate modules preserve each original RFC `scenarioPropertyN`.
For a pattern job, the generated property is:

```maude
rq1RelabelScenario('scenA, 'rq1-...-scenA, scenarioPropertyA) |
rq1RelabelScenario('scenB, 'rq1-...-scenB, scenarioPropertyB) |
...
```

This keeps the original final condition for each scenario, including specific
`@errorLog` checks and normal terminal-state checks, while changing only the
rule label used by the aggregate behavior-deviation set.

## Test Case Counts

The manifest contains only P1-P5 jobs. N/A-classified scenarios are excluded.

| Protocol | Sources | Test Case # |
|---|---|---:|
| TLS 1.2 | `scenario/rfc/5246-core.maude`, `scenario/rfc-additional/5246-core.maude` | 952 |
| TLS 1.3 | `scenario/rfc/8446-core.maude`, `scenario/rfc/hrr.maude`, `scenario/rfc/psk.maude`, `scenario/rfc-additional/8446-core.maude`, `scenario/rfc-additional/hrr.maude`, `scenario/rfc-additional/psk.maude` | 2441 |
| Total | all above | 3393 |

## Usage

Generate aggregate Maude modules and `manifest.json`:

```sh
python3 maude/scenario/rq1/scripts/generate_aggregates.py
```

List jobs:

```sh
python3 maude/scenario/rq1/scripts/run_rq1_generation_time_matrix.py --list-jobs
```

Run a smoke test:

```sh
python3 maude/scenario/rq1/scripts/run_rq1_generation_time_matrix.py \
  --jobs tls13-additional-core-p4 \
  --timeout 120 \
  --tag smoke
```

Run the full matrix:

```sh
python3 maude/scenario/rq1/scripts/run_rq1_generation_time_matrix.py \
  --timeout 86400 \
  --tag table-ii
```

Summarize an existing JSONL result file:

```sh
python3 maude/scenario/rq1/scripts/summarize_generation_time.py
```

Outputs:

| Path | Purpose |
|---|---|
| `state/raw/*.generation.maude` | generated Maude drivers |
| `state/raw/*.generation.out` | Maude stdout |
| `state/raw/*.generation.err` | Maude stderr |
| `state/generation-time-matrix.jsonl` | raw timing records |
| `state/generation-time-summary.csv` | protocol and pattern totals |
| `state/generation-time-summary.md` | Table II draft |
