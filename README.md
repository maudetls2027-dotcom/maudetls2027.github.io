# From Specification Violations to Exploitability: Deviation-Guided Testing of TLS Libraries

---

## Abstract

Transport Layer Security (TLS) libraries implement stateful handshakes in
which message acceptance depends on protocol state and context. A TLS library
may therefore accept a specification-violating message without crashing or
failing visibly. Such bugs are hard to find without a specification-level
oracle -- and even once found, judging exploitability is a separate, largely
manual task.
We address both detection and exploitability by making off-specification
behavior and exploitable outcomes explicit targets for test generation. At its
core is an executable formal model of the TLS handshake, built from the TLS
RFCs, that serves as a specification-level oracle. Over it we define behavior
deviations, parameterized ways a handshake can depart from the specification,
and scenario properties, which steer generation toward outcomes from rejection
through acceptance to completion under an invalid message. Both are reusable
across handshake contexts and extensible for target-specific behavior.
Our framework compiles these into black-box tests against unmodified TLS
libraries and continues each exposed violation on the same library --
automatically when the violated requirement is modeled -- until a completed
handshake is reached, exposing the security impact of the accepted behavior,
such as peer impersonation or connection downgrade. Within the modeled TLS
handshake scope, we find 16 previously unknown specification violations in
recent stable versions of GnuTLS, MbedTLS, and WolfSSL, of which 8 were
confirmed as new vulnerabilities and assigned CVEs; the framework also finds
more RFC-level violations than prior tools.

## Supplementary Materials

The supplementary materials provide additional details that complement the
paper, including extended explanations and supporting information for the
artifact evaluation.

* Supplementary Materials: [PDF](supplementary_materials/main.pdf)

## Artifact Links

* Formal Maude model: [maude/](maude/)

  The executable Maude model contains the TLS handshake specification oracle,
  RFC requirements, message definitions used to generate and check deviation-guided tests.

* Tools: [tools/](tools/)

  The tools directory is reserved for the implementation-side artifact
  components, including the TLS library integration and scripts for generating,
  running, and analyzing black-box tests.
