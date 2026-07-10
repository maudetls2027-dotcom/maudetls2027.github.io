# Tools

This directory contains the implementation-side tooling for the artifact. It
complements the supplementary materials, which describe the formal TLS model,
behavior deviations, scenario properties, and black-box testing workflow.

For reviewers, the three archives correspond to the main implementation stages:

1. `maude-tls-attacker.zip` contains the model-driven test-generation harness.
2. `TLS-Attacker.zip` contains the TLS workflow execution framework used by the
   generated tests.
3. `TLS-Library.zip` contains the target-library integration harness used to run
   those tests against concrete TLS implementations.

## Downloads

- [maude-tls-attacker.zip](https://drive.google.com/file/d/1nvIIuSklgiNjKkoau5kAChn8HPhaIC40/view?usp=share_link)

  This is the archive most directly tied to
  the supplementary-material discussion of the executable Maude TLS model,
  behavior deviations, and scenario properties. It packages the Java/Maude
  harness that converts those model-level specifications into executable
  TLS-Attacker scenarios, together with RFC/CVE scenario resources, generated
  scenario corpora, certificates, configuration files, and Docker/Compose
  scripts for reproducing the generation and execution workflow.

- [TLS-Attacker.zip](https://drive.google.com/file/d/1g_1Z85mVNperbAWg9HQlrwGrckzmiJZc/view?usp=share_link)

  This archive provides the TLS-Attacker
  framework used by the generated tests to send custom TLS handshakes and
  observe target behavior. It includes the Maven source modules, runnable
  client/server/proxy/MITM/trace tools, XML workflow examples, schemas,
  configurations, certificates, and supporting resources for executing generated
  or selected non-standard TLS workflows.

- [TLS-Library.zip](https://drive.google.com/file/d/1p-6u28PRppf2ztEgkRPYyITwgZazZTfL/view?usp=share_link)

  This archive contains the harness used to
  run generated scenarios against concrete TLS library versions. It packages the
  Java runner, ANTLR parsers, profile and runner adapters, certificates,
  generated scenario/profile corpora, profile-overlay artifacts, Docker build
  definitions for multiple TLS libraries, and scripts for launching targets and
  collecting logs.

[Back to artifact overview](../)
