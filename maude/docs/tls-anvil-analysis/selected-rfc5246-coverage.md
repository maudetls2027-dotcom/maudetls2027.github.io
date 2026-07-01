# Selected TLS-Anvil RFC 5246 Coverage

This note covers the TLS-Anvil items selected on 2026-06-13.  I inspected the
extracted `results.zip` contents under
`/private/tmp/tlsanvil-results-20260613-codex`.  The archive did not contain
PCAP/PCAPNG files; the concrete evidence below therefore comes from
`_containerResult.json`, `*_testsuite.log`, and `*_tlsattacker.log`.

## Observed TLS-Anvil Results

| TLS-Anvil item | Affected library/version in results | Observed message flow or value |
|---|---|---|
| `sendAdditionalExtension` | GnuTLS 3.7.0 client, MatrixSSL 4.3.0 client, s2n 0.10.24 client | Client was expected to send a fatal alert but continued with `ClientKeyExchange`, `ChangeCipherSpec`, and `Finished` or left the socket open.  The extra extension type was not serialized in the JSON logs. |
| `selectUnproposedCompressionMethod` | s2n 0.10.24 client | ServerHello selected unoffered compression methods such as `DEFLATE` and `LZS`; client did not produce the expected fatal alert. |
| `acceptsMissingSignature` | s2n 0.10.24 client | ServerKeyExchange signature field omitted; client accepted or kept the socket open. |
| `invalidServerKeyExchangeSignature` | s2n 0.10.24 client | Invalid SKE signatures included bitmask/bit-position mutations such as `SIGNATURE_BITMASK=0,63,69,101,127,255,511` and `BIT_POSITION=0..7`. |
| `acceptsUnproposedNamedGroup` | s2n 0.10.24 client | SKE used groups not offered by the client, including Brainpool, X25519/X448, and SECP/SECT families. |
| `clientMustSendCertMsg` | MatrixSSL 4.3.0 client | After `CertificateRequest`, the client did not send `Certificate`; failed cases included `RECORD_LENGTH=1` and groups `SECP256R1`, `SECP384R1`, `SECP521R1`. |
| `sendNotDefinedRecordTypesWithServerHello`, `sendNotDefinedRecordTypesWithCCSAndFinished` | s2n 0.10.24 client; MatrixSSL 4.3.0 client/server; wolfSSL 4.5.0 server | Undefined record content-type byte was not serialized.  Expected `unexpected_message`; actual behavior was no alert, socket open, decode error, or an unplanned workflow. |
| `acceptAnyRecordVersionNumber` | MatrixSSL 4.3.0 server | Test used arbitrary `{03,XX}` record-layer ClientHello versions; exact `XX` was not serialized.  Server returned fatal `illegal_parameter`. |
| `versionGreaterThanSupportedByServer` | MatrixSSL 4.3.0 server, wolfSSL 4.5.0 server | TLS-Attacker log records ClientHello version `03 0F`; MatrixSSL returned fatal `protocol_version` or `decode_error`. |
| `includeUnknownExtension`, `leaveOutExtensions`, `offerManyCipherSuites` | MatrixSSL 4.3.0 server, wolfSSL debug-x server | Unknown extension type was not serialized.  `offerManyCipherSuites` included unknown/private suite values such as `DF 00..DF C5`, `DF FD`, `DF FF`; servers often produced decode errors or incomplete workflows. |
| `checkExtensions`, `serverRandom` | MatrixSSL 4.3.0 server, wolfSSL 4.5.0 server | ServerHello field/random failures were reported, but the concrete bad random value was not serialized. |
| `offerManyAlgorithms` | LibreSSL 3.2.3 server; MatrixSSL 4.3.0 server; wolfSSL 4.5.0/debug-x server | Many SignatureAndHashAlgorithm values were offered; concrete full list was usually not serialized.  Unknown sig/hash cases logged values like `03 0F`. |
| `includeUnknownSignatureAndHashAlgorithm` | MatrixSSL 4.3.0 server, wolfSSL 4.5.0 server | Unknown SignatureAndHashAlgorithm value logged as `03 0F`; server often returned decode/protocol errors or did not complete the planned workflow. |
| `signatureIsValid` | MatrixSSL 4.3.0 server, wolfSSL 4.5.0/debug-x server | TLS-Anvil expected a valid signed SKE path; affected runs did not execute the expected workflow to completion. |

## Existing Scenario/RFC Coverage

| Item | Existing coverage before this change |
|---|---|
| `sendAdditionalExtension` | Covered for model-known TLS 1.2 ServerHello extensions by `scen25`-`scen31` in `scenario/rfc/5246-core.maude`, backed by ServerHello extension RFC labels. |
| `selectUnproposedCompressionMethod` | Covered by `scen24`, which selects `zlib-compression` even though the client offered only `no-compression`. |
| `invalidServerKeyExchangeSignature` | RFC label existed, but there was no RFC scenario.  Added as `scen46`. |
| `acceptsUnproposedNamedGroup` | RFC label existed, but there was no TLS 1.2 SKE scenario.  Added as `scen51`. |
| `clientMustSendCertMsg` | Happy-flow client-auth scenarios require the message, but there was no omission scenario.  Added as `scen47`. |
| `versionGreaterThanSupportedByServer` | Covered only when interpreted as the ClientHello/ServerHello handshake protocol field, e.g. `scen5`.  Record-layer version compatibility is not covered. |
| `leaveOutExtensions` | Covered for model-known mandatory/required extensions, e.g. `scen8`, `scen44`, `scen45`. |
| `offerManyCipherSuites` | Existing corpus had many single substitutions, not one large offered vector.  Added as `scen48`. |
| `checkExtensions` | Covered for model-known duplicate/forbidden/unrequested extension checks, mainly `scen25`-`scen31`. |
| `offerManyAlgorithms` | Existing corpus had one-at-a-time additions, not one large `signature_algorithms` vector.  Added as `scen49`. |
| `signatureIsValid` | TLS 1.3 CertificateVerify signature scenarios existed.  Added a TLS 1.2 SKE valid-signature reachability scenario as `scen50`. |

## Added RFC 5246 Scenarios

These were added to `maude/scenario/rfc/5246-core.maude`.

| New scen | TLS-Anvil item | Behavior deviation / property |
|---|---|---|
| `scen46` | `invalidServerKeyExchangeSignature` | `setM(#signature, mv[noNonce])` on `buildServerKeyExchangeV2`; client rejects with `decrypt-error`. |
| `scen47` | `clientMustSendCertMsg` | `skip()` on `buildClientCertificateV2`; server rejects the following `ClientKeyExchange` with `unexpected-message`. |
| `scen48` | `offerManyCipherSuites` | Adds a larger cipher-suite vector while preserving `TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256`; handshake reaches both closed states. |
| `scen49` | `offerManyAlgorithms` | Replaces `signature_algorithms` with a larger list including `{ecdsa,sha256}`; handshake reaches both closed states. |
| `scen50` | `signatureIsValid` | Baseline valid TLS 1.2 SKE signature path; SKE is processed and the handshake closes normally. |
| `scen51` | `acceptsUnproposedNamedGroup` | After `processClientHelloV2`, sets server selected supported group to `secp384r1`; generated SKE is rejected with `illegal-parameter` because the client offered `secp256r1`. |

Verification command:

```sh
printf 'red runScenario(TLS-12, initialCWA, initConf1, behaviorDeviationSpecification46, scenarioProperty46) .\nred runScenario(TLS-12, initialCWA, initConf1, behaviorDeviationSpecification47, scenarioProperty47) .\nred runScenario(TLS-12, initialCWA, initConf1, behaviorDeviationSpecification48, scenarioProperty48) .\nred runScenario(TLS-12, initialCWA, initConf1, behaviorDeviationSpecification49, scenarioProperty49) .\nred runScenario(TLS-12, initialCWA, initConf1, behaviorDeviationSpecification50, scenarioProperty50) .\nred runScenario(TLS-12, initialCWA, initConf1, behaviorDeviationSpecification51, scenarioProperty51) .\n' \
  | ./maude/maude-3.5.1/maude -no-advise requirements/5246-core.maude
```

All six reductions returned `NeList{Scen}`.  I also checked representative
tester/target generation: client-side TLS-Anvil items with `tester(N2 . SI)
target(N1 . CI)` generate server-side test actions, and server-side items with
`tester(N1 . CI) target(N2 . SI)` generate client-side test actions.

## Not Immediately Addable

| Item | Why not immediate | Minimal model change plan |
|---|---|---|
| `acceptsMissingSignature` | `#signature` can be corrupted, but `remove(#signature)` is not implemented.  The TLS 1.2 SKE RFC predicate also returns true when the signature field is absent. | Add `remove(#signature)` semantics for `signature(...)`; add an RFC 5246 SKE label requiring a signature for DHE/ECDHE authenticated suites; map the alert to `decrypt-error` or the RFC-appropriate fatal alert; then add the missing-signature scenario. |
| `sendNotDefinedRecordTypesWith*` | `ContentType` is a closed sort with only `handshake`, `change-cipher-spec`, `alert`, and `application-data`. | Add an unknown/invalid content-type constructor, include it in all-values and generation mappings, and add record-layer RFC checks that reject undefined types before message-specific parsing. |
| `acceptAnyRecordVersionNumber` | `#version` can mutate the record version, but TLS 1.2 record-version compatibility rules are not checked as RFC properties.  Arbitrary `{03,XX}` versions are not modeled. | Add record-layer version predicates for TLS 1.0/1.1/1.2 compatibility, extend `ProtocolVersion` or add raw record-version values if SSL3/arbitrary bytes are needed, and wire the checks into receive rules. |
| `includeUnknownExtension` | Unknown/GREASE extension IDs are not represented; only known extension constructors can be added or removed. | Add `unknown-extension(Nat)` or GREASE extension constructors, update duplicate/extension traversal helpers, add client/server ignore-or-reject RFC rules, and expose Java scenario-generation mappings if needed. |
| `serverRandom` | Randoms are symbolic `Nonce` values; byte patterns, timestamp structure, zero/random-quality checks are not modeled. | Add symbolic bad-random constructors such as `zeroRandom`, `gmtUnixTimePattern`, or `repeatedRandom`; add ServerHello random validation properties if these are to be treated as scenario properties. |
| `includeUnknownSignatureAndHashAlgorithm` | Signature algorithms are a closed `{AuthenticationAlgorithm, HashAlgorithm}` vocabulary; true `03 0F` or GREASE values cannot be represented. | Add unknown auth/hash or raw signature-scheme constructors, update `authC`/`hashC` helpers and selection predicates, and map them in all-values / Java generation. |

## Classification Summary

| Group | Classification |
|---|---|
| Already covered by existing RFC scenarios | `sendAdditionalExtension` for known extensions, `selectUnproposedCompressionMethod`, known `leaveOutExtensions`, known `checkExtensions`, handshake-field `versionGreaterThanSupportedByServer`. |
| Added now | `invalidServerKeyExchangeSignature`, `acceptsUnproposedNamedGroup`, `clientMustSendCertMsg`, `offerManyCipherSuites`, `offerManyAlgorithms`, TLS 1.2 SKE `signatureIsValid`. |
| Requires model work | `acceptsMissingSignature`, undefined record content types, exact record-version compatibility, true unknown extensions, concrete `serverRandom` checks, true unknown signature/hash algorithms. |

