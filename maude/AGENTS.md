# Project Agent Instructions

This repository models TLS 1.2 and TLS 1.3 behavior in Maude/Rewriting
Logic. The active work is RFC-check coverage accounting and incremental
implementation for the paper's Section 3 RFC-check coverage table.

## Current Objective

Compute and improve the RFC-check coverage table for the modeled TLS scope.
The table counts only in-scope RFC 5246 and RFC 8446 protocol-level
MUST/MUST NOT requirements that can be checked by the Maude TLS model.

Do not count every normative sentence in the RFCs. Count only requirements
that belong to the paper's modeled TLS feature scope:

- TLS 1.2 and TLS 1.3 handshake message exchange.
- Authentication, certificate, and signature-validation behavior.
- Cryptographic parameter negotiation.
- Transcript/key-schedule context checks represented by the model.
- Session, resumption, renegotiation, PSK, post-handshake authentication,
  NewSessionTicket, HelloRetryRequest, and KeyUpdate behavior when represented
  by the model.

Out of scope for the RFC-check table unless explicitly represented as a
Maude-level validation predicate:

- Record-protection algorithm internals.
- Concrete cryptographic primitive implementations.
- TCP, timing, fragmentation, retransmission, I/O, and deployment behavior.
- RFC SHOULD/MAY guidance.
- Pure sender construction advice that has no modeled receiver-side or
  transition-level validation.
- Implementation-library details outside RFC 5246/RFC 8446.

## Source of Truth

- TLS 1.2: `docs/specs/tls/rfc5246.txt`
- TLS 1.3: `docs/specs/tls/rfc8446.txt`
- TLS 1.2 secure renegotiation, when needed: `docs/specs/tls/rfc5746.txt`
- Existing requirement labels and alert mapping: `rfc-requirements.maude`
- TLS receive/send rules: `api/accept-v2.maude`, `api/connect-v2.maude`,
  `api/accept-v3.maude`, `api/connect-v3.maude`
- Scenario evidence: `scenario/rfc/`, `requirements/`
- Paper scope: Section 3.2, "Modeling Scope"
- Appendix evidence draft: Appendix C RFC Requirement Labels

## RFC-Check Classes

Use exactly these classes for the paper table unless the user changes the
table:

- `syntax`: vector bounds, parseable handshake body, record/message framing,
  content type, handshake type syntax, and length consistency.
- `state`: expected handshake type, expected record content type, and
  current-state-dependent message acceptance.
- `extension`: duplicate extensions, mandatory extensions, forbidden
  extensions, unsolicited extension responses, and message-specific extension
  allowlists.
- `negotiation`: version, cipher suite, compression method, named group, key
  share, signature algorithm, PSK mode, PSK identity, and related
  offer/selection consistency.
- `auth`: certificate-list requirements, certificate/key compatibility,
  acceptable signature algorithms, certificate signature validation, and client
  authentication gating.
- `ctx`: transcript-dependent CertificateVerify/Finished validation,
  protected-message context, binder validation, and key-schedule-dependent
  checks represented in the model.
- `sess`: session/resumption/post-handshake validation, including TLS 1.2
  renegotiation information, TLS 1.2 resumption when in scope, TLS 1.3 PSK,
  NewSessionTicket, post-handshake authentication, HelloRetryRequest
  continuation constraints, and KeyUpdate.

## Counting Rules

For `N_class`:

1. Extract atomic RFC 5246/RFC 8446 MUST/MUST NOT obligations inside the
   modeled scope.
2. Split a compound sentence into separate obligations when the model can check
   each obligation independently.
3. Count a repeated RFC obligation once unless it applies to distinct message
   contexts with distinct receiver states or distinct Maude requirement
   targets.
4. Record message type, endpoint role, RFC number, RFC section, class,
   requirement paraphrase, inclusion rationale, and exclusion rationale if
   excluded.

For `M_class`:

1. Count a requirement as implemented only when there is explicit Maude evidence
   that violating input is rejected or made unreachable.
2. Accept evidence from `rfc-requirement(...)` equations, `checkRequirements`,
   receive-rule guards, `messageError`, state-transition guards, or scenario
   tests that directly exercise the requirement.
3. Sender-side construction alone is partial evidence unless the requirement is
   only about model-generated valid behavior and there is no receiver-side
   analogue.
4. A broad helper may support an implemented requirement, but the audit must
   name the concrete requirement label and the process rule or error path that
   invokes it.
5. Do not count a requirement as implemented if it is merely present in Appendix
   C or in comments without executable Maude semantics.

Use these implementation statuses:

- `implemented`: explicit executable check exists and is invoked on the relevant
  path.
- `partial`: model has related vocabulary or construction behavior but no full
  reject/accept validation for the requirement.
- `small-patch`: likely implementable by adding a local `rfc-requirement`
  equation, alert mapping, guard invocation, or focused scenario.
- `new-semantics`: requires new state, message fields, transcript/key-schedule
  representation, or broader rule changes.
- `out-of-scope`: not part of Section 3 modeled scope.
- `uncertain`: evidence is ambiguous; needs manual review before counting.

## Required Workflow

1. Read Section 3.2 and keep the modeled TLS scope fixed before mining RFCs.
2. Mine RFC 5246 and RFC 8446 for in-scope MUST/MUST NOT obligations.
3. Classify each obligation into one RFC-check class.
4. Map each obligation to existing Maude implementation evidence.
5. Produce the per-class `N`, `M`, and gap list.
6. Triage gaps into `small-patch` versus `new-semantics`.
7. Implement only `small-patch` items when the user asks to proceed.
8. After implementation, run focused scenarios plus relevant regression suites.

## Subagent Roles

Configured subagents under `.codex/agents/` should be used as follows:

- `rfc_requirement_miner`: read-only RFC extraction and classification.
- `maude_implementation_auditor`: read-only mapping from RFC obligations to
  Maude evidence.
- `rfc_check_developer`: workspace-write implementation of selected
  small-patch gaps.
- `rfc_check_tester`: workspace-write validation and coverage evidence.
- `cve_rfc_mapper`: read-only support for mapping CVE-triggering malformed
  behavior to missed RFC checks when needed.

Do not spawn subagents unless the parent task explicitly asks for delegation or
parallel agent work.

## Implementation Discipline

- Follow existing Maude module organization, state representation, message
  constructors, operator naming, equation labels, rule labels, and scenario
  style.
- Prefer extending `rfc-requirements.maude` and existing `api/*` process-rule
  guards over creating parallel validation machinery.
- Keep `op rfc-requirement : RFCRequirementTarget RFCLabel MsgContent Object -> Bool .`
  as the central requirement predicate unless the user explicitly approves a
  redesign.
- Add or update `getAlertDescription` consistently with each new label.
- Keep labels local to their target, such as `tls13-server-hello, label[20]`.
- Add adjacent comments with RFC number, section, class, and requirement
  paraphrase for new requirement equations.
- Do not weaken existing checks or remove scenario coverage.
- Avoid unrelated refactors while increasing coverage.

## Maude Object-Module Guardrail

In `omod`, partial object patterns such as `< O : C | attr : V >` can match
complete objects, and omitted attributes can be preserved by object-module
semantics. Do not reject or rewrite such patterns solely because the same
literal does not reduce standalone in `mod`/`fmod`.

## Required Scenario Execution

All Maude scenario experiments must use:

```maude
red runScenario(system, scenY) .
```

Do not treat a load-only check as a scenario pass. For each executed scenario,
confirm that `runScenario` returns an actual `ScenarioResult` or
`NeList{ScenarioResult}`, not `(nil).List{ScenarioResult}`.

Relevant regression suites:

- RFC 5246 core: `requirements/5246-core.maude`
- RFC 8446 core: `requirements/8446-core.maude`
- HRR: `requirements/hrr.maude`
- PSK: `requirements/psk.maude`

Run the smallest focused suite needed for a narrow patch, then broaden to the
affected core/HRR/PSK suite before reporting completion.
