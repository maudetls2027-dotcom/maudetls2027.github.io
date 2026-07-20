# Tools

This page provides the implementation components, benchmark inputs, and
orchestration scripts for the artifact. It complements the supplementary
materials, which describe the formal TLS model, behavior deviations, scenario
properties.

Download all four archives and the separate scripts directory.
Extract the archives into a common artifact directory and place the downloaded
scripts directory alongside them. The scripts directory contains `ReadMe.md`,
which provides the required directory layout, software installation
instructions, Docker image build procedure, and benchmark execution commands.

The downloads correspond to the following artifact components:

1. `maude-tls-attacker.zip` contains the model-driven test-generation and tester
   harness.
2. `TLS-Attacker.zip` contains the TLS workflow execution framework used by the
   generated tests.
3. `TLS-Library.zip` contains the target-library integration harness used to run
   concrete TLS implementations.
4. `benchmark.zip` contains the CVE benchmark inputs.
5. The scripts directory contains the common build and execution entrypoints
   and the centralized artifact guide.

## Downloads

- [maude-tls-attacker.zip](https://drive.google.com/file/d/1nvIIuSklgiNjKkoau5kAChn8HPhaIC40/view?usp=share_link)

  This archive contains the Java and Maude harness that transforms formal TLS
  behavior descriptions into executable tester scenarios. It includes the TLS
  formal model, DSL parsers, RFC- and CVE-specific scenario modules,
  certificates, runtime resources, and the Docker definition for the MTA tester
  image. The image is built against the separately downloaded local
  `TLS-Attacker` source.

- [TLS-Attacker.zip](https://drive.google.com/file/d/1g_1Z85mVNperbAWg9HQlrwGrckzmiJZc/view?usp=share_link)

  This archive contains the TLS workflow execution framework used by the MTA
  tester. It provides the Maven source modules, TLS message and workflow
  implementations, client/server/proxy tools, schemas, configurations,
  certificates, and artifact-specific extensions required by the generated
  tests. The artifact build compiles this local source and includes the resulting
  libraries in the MTA Docker image.

- [TLS-Library.zip](https://drive.google.com/file/d/1p-6u28PRppf2ztEgkRPYyITwgZazZTfL/view?usp=share_link)

  This archive contains the target-library integration harness. It includes the
  Java profile parser and runner adapters, native wrapper sources, certificates,
  runtime resources, and version-specific Docker definitions for executing the
  generated tests against concrete TLS library versions.

- [benchmark.zip](https://drive.google.com/file/d/1Ar0GK--Hxux5qhkhVJTdqB3wPioFRAB5/view?usp=share_link)

  This archive contains the CVE benchmark inputs under `benchmarks/`. Each
  benchmark variant provides the TLS profile, behavior deviation, and scenario
  DSL files required for tester-scenario generation and execution.

- [scripts directory](https://drive.google.com/drive/folders/1qI5OACJSI2n5mT9aFaESz_mMpcOW8VBU?usp=share_link)

  This directory provides `docker-build.py`, `run-benchmark.py`, and the
  centralized `ReadMe.md` guide. The build script compiles the downloaded local
  TLS-Attacker source, builds the MTA tester image, and builds selected
  TLS-Library target images. The benchmark runner generates tester scenarios,
  executes the MTA and target containers, and records the resulting raw and
  Docker logs.

  Download this directory as `scripts/`, place it alongside the extracted
  implementation and benchmark directories, and follow `scripts/ReadMe.md` for
  the complete build and execution procedure.

[Back to artifact overview](../)