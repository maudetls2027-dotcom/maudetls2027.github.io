# RFC-Check Implementation Numerator v1

This file records the implemented numerator for the RFC-check coverage table in `denominator-v1.md`.

Counting rule: only rows marked **Implemented** are counted in `M`. Rows marked **Partial** have some Maude support but are not counted because the modeled behavior does not cover the whole RFC requirement selected in the denominator. Line references point to the current Maude sources in this workspace.

## Final Numerator

| RFC-check class | Denominator `N` | Implemented `M` | Partial | Not implemented | Coverage |
|---|---:|---:|---:|---:|---:|
| Syntax/length check | 13 | 11 | 1 | 1 | 84.6% |
| Message order expectation | 19 | 10 | 8 | 1 | 52.6% |
| Extension validity | 23 | 14 | 7 | 2 | 60.9% |
| Negotiation consistency | 30 | 17 | 8 | 5 | 56.7% |
| Authentication validation | 36 | 19 | 13 | 4 | 52.8% |
| Cryptographic-context validation | 15 | 7 | 7 | 1 | 46.7% |
| Session/resumption/post-handshake validation | 32 | 11 | 9 | 12 | 34.4% |
| **Total** | **168** | **89** | **53** | **26** | **53.0%** |

```text
M_syn   = 11
M_state = 10
M_ext   = 14
M_neg   = 17
M_auth  = 19
M_ctx   = 7
M_sess  = 11
M_total = 89
```

## RFC Breakdown

| RFC | Syntax | State | Extension | Negotiation | Authentication | Context | Session | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| RFC 5246 implemented | 7 | 4 | 2 | 6 | 8 | 4 | 4 | 35 |
| RFC 5246 partial | 1 | 3 | 4 | 5 | 7 | 4 | 0 | 24 |
| RFC 5246 not implemented | 0 | 0 | 0 | 2 | 2 | 1 | 3 | 8 |
| RFC 8446 implemented | 4 | 6 | 12 | 11 | 11 | 3 | 7 | 54 |
| RFC 8446 partial | 0 | 5 | 3 | 3 | 6 | 3 | 9 | 29 |
| RFC 8446 not implemented | 1 | 1 | 2 | 3 | 2 | 0 | 9 | 18 |

## Detailed Implementation Inventory

### Syntax (`M_syn = 11 / N_syn = 13`)

| ID | Status | Maude evidence | Assessment |
|---|---|---|---|
| `5246-SYN-01` | Partial | `maude/tls-message.maude:24-28`, `maude/api/common-aux.maude:417-432`, `maude/api/common-aux.maude:496-517` | Record fields and symbolic `valid` lengths exist, but concrete plaintext bounds and zero-length prohibitions are not modeled. |
| `5246-SYN-02` | Implemented | `maude/api/connect-v2.maude:24-36`, `maude/api/accept-v2.maude:48-63`, `maude/rfc-requirements.maude:1438-1449` | ClientHello builder/process path includes expected fields and symbolic size checks. |
| `5246-SYN-03` | Implemented | `maude/api/accept-v2.maude:82-97`, `maude/api/connect-v2.maude:68-92`, `maude/rfc-requirements.maude:1503-1514` | ServerHello builder/process path includes fixed fields, extensions, and symbolic size/type checks. |
| `5246-SYN-04` | Implemented | `maude/tls-message.maude:50-51`, `maude/api/accept-v2.maude:122-134`, `maude/rfc-requirements.maude:1562-1586` | Certificate messages use certificate vectors with symbolic length checks. |
| `5246-SYN-05` | Implemented | `maude/api/accept-v2.maude:169-216`, `maude/api/connect-v2.maude:146-165`, `maude/rfc-requirements.maude:1712-1743` | ServerKeyExchange is skipped/constructed by key exchange mode; DHE/ECDHE signatures are built and checked. |
| `5246-SYN-06` | Implemented | `maude/api/accept-v2.maude:243-256`, `maude/api/connect-v2.maude:189-200`, `maude/rfc-requirements.maude:1755-1768` | CertificateRequest vector syntax and symbolic length checks are modeled. |
| `5246-SYN-07` | Implemented | `maude/api/connect-v2.maude:297-322`, `maude/api/accept-v2.maude:334-358`, `maude/rfc-requirements.maude:1636-1647` | ClientKeyExchange body is selected from RSA/DH/ECDH key exchange constructors. |
| `5246-SYN-08` | Implemented | `maude/tls-message.maude:36-37`, `maude/api/connect-v2.maude:367-374`, `maude/rfc-requirements.maude:1802-1808` | CCS is a single symbolic constructor carried under CCS content type. |
| `8446-SYN-01` | Implemented | `maude/rfc-requirements.maude:585-590`, `maude/rfc-requirements.maude:749-754`, `maude/rfc-requirements.maude:829-838`, `maude/rfc-requirements.maude:919-922`, `maude/rfc-requirements.maude:956-959`, `maude/rfc-requirements.maude:1208-1252` | TLS 1.3 message content-type checks exist and are reachable through `messageError`/process paths. |
| `8446-SYN-02` | Implemented | `maude/api/connect-v3.maude:36-52`, `maude/rfc-requirements.maude:659-667` | ClientHello builder fixes legacy version/compression and receiver checks TLS 1.3 ClientHello version syntax. |
| `8446-SYN-03` | Implemented | `maude/api/accept-v3.maude:163-180`, `maude/rfc-requirements.maude:829-838`, `maude/rfc-requirements.maude:904-906` | ServerHello builder uses TLS 1.2 legacy version and receiver checks ServerHello syntax/type/version. |
| `8446-SYN-04` | Not implemented | `maude/rfc-requirements.maude:1794-1809` | TLS 1.3 compatibility CCS accept/drop window is not modeled; only TLS 1.2 CCS checks exist. |
| `8446-SYN-05` | Implemented | `maude/tls-data.maude:74-80`, `maude/rfc-requirements.maude:1180-1187`, `maude/api/accept-v3.maude:586-590`, `maude/api/connect-v3.maude:628-631` | `KeyUpdateRequest` has an `unknown` constructor and receivers reject it. |

### Message Order Expectation (`M_state = 10 / N_state = 19`)

| ID | Status | Maude evidence | Assessment |
|---|---|---|---|
| `5246-STA-01` | Partial | `maude/api/connect-v2.maude:24-36`, `maude/api/accept-v2.maude:48-50`, `maude/rfc-requirements.maude:1862-1865`, `maude/rfc-requirements.maude:1903-1905` | Initial and renegotiation ClientHello states exist; HelloRequest is not modeled. |
| `5246-STA-02` | Partial | `maude/handshake-state.maude:13-16`, `maude/handshake-state.maude:48-51`, `maude/rfc-requirements.maude:1862-1905`, `maude/api/accept-v2.maude:529-538` | State ordering is encoded, but some fatal error dispatches pass empty objects, so state-specific error checks are not fully wired. |
| `5246-STA-03` | Implemented | `maude/api/accept-v2.maude:117-120`, `maude/api/accept-v2.maude:169-190`, `maude/api/connect-v2.maude:108-165` | Server Certificate skip and ServerKeyExchange transitions encode the required position. |
| `5246-STA-04` | Implemented | `maude/api/accept-v2.maude:169-173`, `maude/api/accept-v2.maude:232-256`, `maude/api/connect-v2.maude:184-200` | CertificateRequest only follows the ServerKeyExchange/certificate phase. |
| `5246-STA-05` | Implemented | `maude/api/connect-v2.maude:238-312`, `maude/api/accept-v2.maude:291-350` | ClientKeyExchange follows client Certificate when present, or the skip state otherwise. |
| `5246-STA-06` | Implemented | `maude/api/connect-v2.maude:339-355`, `maude/api/accept-v2.maude:372-388` | CertificateVerify is immediately after ClientKeyExchange when sent. |
| `5246-STA-07` | Partial | `maude/api/connect-v2.maude:367-454`, `maude/api/accept-v2.maude:400-486`, `maude/rfc-requirements.maude:1882-1901` | Finished-after-CCS is state-enforced; fatal handling for wrong-point Finished is only partially wired. |
| `8446-STA-01` | Implemented | `maude/rfc-requirements.maude:1207-1252`, `maude/api/connect-v3.maude:205-238`, `maude/api/connect-v3.maude:266-306`, `maude/api/connect-v3.maude:327-398` | State-specific process guards and `messageError` dispatch enforce expected next messages. |
| `8446-STA-02` | Partial | `maude/api/accept-v3.maude:41-73`, `maude/api/connect-v3.maude:98-111`, `maude/rfc-requirements.maude:722-724` | Initial/HRR ClientHello paths and renegotiation signaling rejection exist, but post-handshake ClientHello rejection is not explicit. |
| `8446-STA-03` | Implemented | `maude/rfc-requirements.maude:318-320`, `maude/rfc-requirements.maude:791-793`, `maude/api/connect-v3.maude:153-173` | A second HRR is rejected by transcript/HRR checks. |
| `8446-STA-04` | Implemented | `maude/api/accept-v3.maude:206-214`, `maude/api/connect-v3.maude:266-276`, `maude/rfc-requirements.maude:924-927` | Server builds EncryptedExtensions after ServerHello and client processes it only in the matching state. |
| `8446-STA-05` | Implemented | `maude/api/connect-v3.maude:294-306`, `maude/rfc-requirements.maude:961-966` | CertificateRequest is processed after EncryptedExtensions, or Certificate may be next. |
| `8446-STA-06` | Implemented | `maude/api/connect-v3.maude:321-398`, `maude/api/accept-v3.maude:271-337` | Authentication flight order is Certificate, CertificateVerify, Finished, with PSK skips. |
| `8446-STA-07` | Implemented | `maude/api/connect-v3.maude:327-398`, `maude/api/accept-v3.maude:365-453`, `maude/rfc-requirements.maude:1096-1099`, `maude/rfc-requirements.maude:1141-1144` | CertificateVerify follows Certificate and precedes Finished in both directions. |
| `8446-STA-08` | Partial | `maude/api/connect-v3.maude:416-432`, `maude/rfc-requirements.maude:1027-1029` | Client Certificate is skipped when not requested and built when requested, but empty client-certificate behavior is not fully RFC-compatible. |
| `8446-STA-09` | Partial | `maude/api/connect-v3.maude:386-401`, `maude/api/accept-v3.maude:327-337` | Application traffic keys are derived only after Finished, but ordinary application-data processing is otherwise not modeled. |
| `8446-STA-10` | Not implemented | `maude/tls-data.maude:10-16` | `EndOfEarlyData` is absent from handshake types and has no build/process rules. |
| `8446-STA-11` | Partial | `maude/api/connect-v3.maude:538-552`, `maude/api/accept-v3.maude:497-509`, `maude/rfc-requirements.maude:949-954` | PHA CertificateRequest/response chain exists, but alert coverage is only on the modeled PHA path. |
| `8446-STA-12` | Partial | `maude/api/connect-v3.maude:571-582`, `maude/api/connect-v3.maude:619-655`, `maude/api/accept-v3.maude:524-590` | KeyUpdate rules only exist after Finished states; pre-Finished receipt is not explicitly alerted. |

### Extension Validity (`M_ext = 14 / N_ext = 23`)

| ID | Status | Maude evidence | Assessment |
|---|---|---|---|
| `5246-EXT-01` | Partial | `maude/rfc-requirements.maude:1284-1291`, `maude/rfc-requirements.maude:1448-1460`, `maude/api/common-aux.maude:496-517` | Supported extension forms are checked, but malformed concrete lengths and absent extension-tail behavior are abstract. |
| `5246-EXT-02` | Partial | `maude/rfc-requirements.maude:1321-1330`, `maude/rfc-requirements.maude:1529-1531`, `maude/api/common-aux.maude:393-396`, `maude/api/connect-v2.maude:82-92` | Server builder selects allowed extensions, but client-side unsolicited-extension check is not fully wired to client state. |
| `5246-EXT-03` | Implemented | `maude/api/common-aux.maude:266-278`, `maude/rfc-requirements.maude:1469-1470`, `maude/rfc-requirements.maude:1520-1521` | Duplicate ClientHello/ServerHello extensions are rejected. |
| `5246-EXT-04` | Implemented | `maude/rfc-requirements.maude:1294-1296`, `maude/rfc-requirements.maude:1466-1467` | Anonymous signature algorithms are explicitly forbidden. |
| `5246-EXT-05` | Partial | `maude/rfc-requirements.maude:1462-1464`, `maude/api/common-aux.maude:228-244`, `maude/api/accept-v2.maude:51-63` | SignatureAlgorithms use exists, but server-side policy needs state not passed by the current process call. |
| `5246-EXT-06` | Partial | `maude/rfc-requirements.maude:1526-1527`, `maude/api/common-aux.maude:247-254`, `maude/api/accept-v2.maude:94-97` | Server prohibition is modeled; pre-TLS-1.2 ClientHello behavior is outside the TLS 1.2-only path. |
| `8446-EXT-01` | Partial | `maude/api/common-aux.maude:68-131` | Server selection ignores unsupported/unselected known extensions; generic unknown ClientHello extensions are not represented. |
| `8446-EXT-02` | Not implemented | `maude/rfc-requirements.maude:397-399`, `maude/rfc-requirements.maude:976-978` | CertificateRequest validation exists, but NewSessionTicket extensions are not modeled. |
| `8446-EXT-03` | Partial | `maude/rfc-requirements.maude:340-347`, `maude/rfc-requirements.maude:884-886`, `maude/rfc-requirements.maude:291-297`, `maude/rfc-requirements.maude:807-809` | ServerHello unsolicited responses are checked and HRR cookie is allowlisted, but the rule is not generalized across all response contexts. |
| `8446-EXT-04` | Implemented | `maude/rfc-requirements.maude:328-337`, `maude/rfc-requirements.maude:390-399`, `maude/rfc-requirements.maude:807-809`, `maude/rfc-requirements.maude:888-890`, `maude/rfc-requirements.maude:933-935`, `maude/rfc-requirements.maude:976-978` | Forbidden-message extension allowlists exist for ServerHello/HRR/EncryptedExtensions/CertificateRequest. |
| `8446-EXT-05` | Partial | `maude/api/common-aux.maude:266-278`, `maude/rfc-requirements.maude:718-720`, `maude/rfc-requirements.maude:771-773`, `maude/rfc-requirements.maude:896-898`, `maude/rfc-requirements.maude:972-974` | Duplicate checks exist for ClientHello/HRR/ServerHello/CertificateRequest; no EncryptedExtensions duplicate label. |
| `8446-EXT-06` | Not implemented | `maude/tls-data.maude:273-287` | `Extension` is associative-commutative, so extension order is erased and `pre_shared_key` last cannot be checked. |
| `8446-EXT-07` | Implemented | `maude/rfc-requirements.maude:659-667`, `maude/rfc-requirements.maude:685-694`, `maude/rfc-requirements.maude:803-805`, `maude/rfc-requirements.maude:856-858` | ClientHello/ServerHello/HRR `supported_versions` requirements are checked. |
| `8446-EXT-08` | Implemented | `maude/rfc-requirements.maude:291-297`, `maude/rfc-requirements.maude:803-809`, `maude/api/accept-v3.maude:132-143` | HRR `supported_versions` and HRR-only extension allowlist are enforced by checks/build filtering. |
| `8446-EXT-09` | Implemented | `maude/rfc-requirements.maude:643-650`, `maude/rfc-requirements.maude:685-694`, `maude/rfc-requirements.maude:397-399`, `maude/rfc-requirements.maude:976-978` | Certificate authentication requires `signature_algorithms`; CertificateRequest must include it. |
| `8446-EXT-10` | Implemented | `maude/rfc-requirements.maude:685-694`, `maude/rfc-requirements.maude:703-712` | Non-PSK TLS 1.3 handshakes require `supported_groups` and group overlap. |
| `8446-EXT-11` | Implemented | `maude/rfc-requirements.maude:685-694` | `supported_groups` and `key_share` must appear together in the modeled ClientHello checks. |
| `8446-EXT-12` | Implemented | `maude/api/accept-v3.maude:90-96`, `maude/api/accept-v3.maude:186-188` | PSK agreement is unreachable without `pre_shared_key`; selected PSK response is built only from matching PSK info. |
| `8446-EXT-13` | Implemented | `maude/rfc-requirements.maude:620-622` | `pre_shared_key` requires `psk_key_exchange_modes`. |
| `8446-EXT-14` | Implemented | `maude/rfc-requirements.maude:860-862`, `maude/api/common-aux.maude:247-254` | ServerHello rejects `psk_key_exchange_modes`, and builder filtering omits it. |
| `8446-EXT-15` | Implemented | `maude/rfc-requirements.maude:613-618`, `maude/api/connect-v3.maude:126-132` | `early_data` requires PSK and early-data build path depends on PSK info. |
| `8446-EXT-16` | Implemented | `maude/rfc-requirements.maude:949-954`, `maude/api/common-aux.maude:262-264` | PHA CertificateRequest requires client PHA support and server-side filtering omits `post_handshake_auth`. |
| `8446-EXT-17` | Implemented | `maude/rfc-requirements.maude:390-394`, `maude/rfc-requirements.maude:933-935`, `maude/api/connect-v3.maude:272-276` | EncryptedExtensions forbidden extensions are rejected by allowlist checks. |

### Negotiation Consistency (`M_neg = 17 / N_neg = 30`)

| ID | Status | Maude evidence | Assessment |
|---|---|---|---|
| `5246-NEG-01` | Implemented | `maude/rfc-requirements.maude:1539-1540`, `maude/api/connect-v2.maude:68-92` | Client accepts only TLS 1.2 ServerHello in this model. |
| `5246-NEG-02` | Not implemented | `maude/rfc-requirements.maude:1482-1483`, `maude/api/accept-v2.maude:43-51`, `maude/scenario/rfc/5246-core.maude:165-172` | Higher ClientHello versions are rejected instead of negotiating down to the highest supported version. |
| `5246-NEG-03` | Implemented | `maude/rfc-requirements.maude:1482-1483`, `maude/scenario/rfc/5246-core.maude:165-172` | Unsupported client protocol version yields `protocol-version`. |
| `5246-NEG-04` | Not implemented | `maude/api/common-aux.maude:417-428` | Record-layer `{03,XX}` compatibility is not represented; record versions are symbolic/fixed. |
| `5246-NEG-05` | Implemented | `maude/api/connect-v2.maude:302-320`, `maude/api/accept-v2.maude:346-387` | RSA PMS carries the selected ClientHello version on the client side; the server checks the RSA PMS version and continues with a random PMS on mismatch or malformed RSA PMS processing. |
| `5246-NEG-06` | Partial | `maude/api/common-aux.maude:60-62`, `maude/api/accept-v2.maude:48-49`, `maude/rfc-requirements.maude:1476-1477` | Overlap selection exists, but unrecognized suites and full stateful receive checks are incomplete. |
| `5246-NEG-07` | Partial | `maude/api/accept-v2.maude:48-49`, `maude/api/accept-v2.maude:93-96`, `maude/api/common-aux.maude:401-415`, `maude/rfc-requirements.maude:1536-1537` | Server construction/session value are modeled; client receive check is not fully wired. |
| `5246-NEG-08` | Implemented | `maude/ciphersuite.maude:103`, `maude/ciphersuite.maude:130-218` | `TLS_NULL_WITH_NULL_NULL` has no constructor and cannot be negotiated. |
| `5246-NEG-09` | Implemented | `maude/configuration.maude:18`, `maude/api/common-aux.maude:60-62`, `maude/api/connect-v2.maude:108-113`, `maude/ciphersuite.maude:334-391` | Anonymous suites are selected only if configured; anonymous paths suppress certificate/auth messages. |
| `5246-NEG-10` | Implemented | `maude/rfc-requirements.maude:1479-1480`, `maude/scenario/rfc/5246-core.maude:12-13` | ClientHello compression list must contain `no-compression`. |
| `5246-NEG-11` | Partial | `maude/api/common-aux.maude:64-66`, `maude/api/common-aux.maude:401-415`, `maude/rfc-requirements.maude:1533-1534` | Compression selection/session value exist; client receive check is not fully wired. |
| `5246-NEG-12` | Implemented | `maude/api/accept-v2.maude:200-204` | Absent `signature_algorithms` falls back to the cipher-suite default algorithm pair. |
| `5246-NEG-13` | Partial | `maude/rfc-requirements.maude:1455-1457`, `maude/rfc-requirements.maude:1736-1741`, `maude/api/accept-v2.maude:48-49` | Related checks exist, but cipher-suite selection itself does not filter candidates by `signature_algorithms`. |
| `8446-NEG-01` | Partial | `maude/api/common-aux.maude:68-73`, `maude/rfc-requirements.maude:659-667` | Server selects common `supported_versions` and ClientHello must offer TLS 1.3, but generic unknown versions are not represented. |
| `8446-NEG-02` | Not implemented | `maude/rfc-requirements.maude:685-694` | TLS 1.3 path rejects missing `supported_versions` instead of falling back to TLS 1.2. |
| `8446-NEG-03` | Implemented | `maude/rfc-requirements.maude:900-906`, `maude/rfc-requirements.maude:856-858`, `maude/api/connect-v3.maude:219-238` | Client checks that ServerHello selected version was offered and requires ServerHello `supported_versions`. |
| `8446-NEG-04` | Not implemented | `maude/rfc-requirements.maude:856-858`, `maude/rfc-requirements.maude:900-906` | Older-server fallback path is not modeled in TLS 1.3 ServerHello processing. |
| `8446-NEG-05` | Not implemented | `maude/api/accept-v3.maude:173-180`, `maude/tls-data.maude:68-72` | No downgrade sentinel field/check exists; ServerHello random is ordinary `nonce`, while only HRR has special `hrrNonce`. |
| `8446-NEG-06` | Implemented | `maude/api/common-aux.maude:60-62`, `maude/rfc-requirements.maude:714-716` | Cipher-suite overlap uses `select`, ignoring unsupported entries and aborting on no overlap. |
| `8446-NEG-07` | Partial | `maude/rfc-requirements.maude:783-785`, `maude/rfc-requirements.maude:892-894` | Offered cipher checks exist for ServerHello/HRR, but post-HRR ServerHello retaining HRR cipher suite is not fully checked. |
| `8446-NEG-08` | Implemented | `maude/rfc-requirements.maude:624-641` | TLS 1.3 ClientHello rejects non-TLS-1.3 cipher suites. |
| `8446-NEG-09` | Implemented | `maude/rfc-requirements.maude:696-701`, `maude/rfc-requirements.maude:864-866`, `maude/api/connect-v3.maude:47-52`, `maude/api/accept-v3.maude:175-177` | TLS 1.3 compression is fixed to `no-compression` in ClientHello/ServerHello. |
| `8446-NEG-10` | Implemented | `maude/rfc-requirements.maude:703-712`, `maude/api/accept-v3.maude:75-80` | Non-PSK group overlap is required; HRR is chosen when no compatible initial key share exists. |
| `8446-NEG-11` | Implemented | `maude/rfc-requirements.maude:703-716` | No common cipher/group parameters abort through ClientHello labels 4/5. |
| `8446-NEG-12` | Implemented | `maude/api/accept-v3.maude:77-80`, `maude/api/accept-v3.maude:132-143` | Missing compatible initial key share leads to HRR state/build. |
| `8446-NEG-13` | Implemented | `maude/rfc-requirements.maude:283-288`, `maude/rfc-requirements.maude:726-731` | KeyShareEntry order/subset helper and label are present. |
| `8446-NEG-14` | Implemented | `maude/rfc-requirements.maude:652-657`, `maude/rfc-requirements.maude:726-731` | Duplicate key share and outside-supported-groups shares are rejected. |
| `8446-NEG-15` | Implemented | `maude/rfc-requirements.maude:795-801`, `maude/api/connect-v3.maude:176-183`, `maude/api/connect-v3.maude:98-111` | HRR selected group must be supported/not already offered, and retry key share is generated. |
| `8446-NEG-16` | Implemented | `maude/tls-data.maude:296-298`, `maude/rfc-requirements.maude:350-361`, `maude/rfc-requirements.maude:876-882` | Server key_share is single-entry and must match offered/supported group. |
| `8446-NEG-17` | Partial | `maude/rfc-requirements.maude:603-611`, `maude/rfc-requirements.maude:848-854`, `maude/rfc-requirements.maude:872-874` | PSK mode/key_share constraints and selected identity range are checked, but PSK/cipher hash compatibility is not fully checked. |

### Authentication Validation (`M_auth = 19 / N_auth = 36`)

| ID | Status | Maude evidence | Assessment |
|---|---|---|---|
| `5246-AUTH-01` | Implemented | `maude/api/accept-v2.maude:117-134`, `maude/api/connect-v2.maude:108-113` | Server Certificate is built for non-anonymous authentication and skipped for anonymous suites. |
| `5246-AUTH-02` | Partial | `maude/rfc-requirements.maude:1345-1348`, `maude/rfc-requirements.maude:1618-1620`, `maude/api/accept-v2.maude:131-133` | Public-key/cipher-suite check exists, but builder mainly filters by signature algorithm and receive check lacks state. |
| `5246-AUTH-03` | Partial | `maude/rfc-requirements.maude:1356-1361`, `maude/rfc-requirements.maude:1602-1612`, `maude/tls-data.maude:194-208` | Symbolic certificate signature/issuer checks exist; ordered chain certification is not fully modeled. |
| `5246-AUTH-04` | Implemented | `maude/tls-data.maude:194-208` | Certificates are represented only by the `x509(...)` constructor. |
| `5246-AUTH-05` | Not implemented | `maude/tls-data.maude:197-208`, `maude/rfc-requirements.maude:1345-1348` | No keyUsage/keyEncipherment certificate field is modeled. |
| `5246-AUTH-06` | Partial | `maude/rfc-requirements.maude:1392-1398`, `maude/rfc-requirements.maude:1736-1741` | Signing algorithm compatibility is modeled; keyUsage `digitalSignature` is not. |
| `5246-AUTH-07` | Partial | `maude/rfc-requirements.maude:1392-1398`, `maude/rfc-requirements.maude:1736-1741` | DSS signing compatibility is modeled; keyUsage is not. |
| `5246-AUTH-08` | Not implemented | `maude/api/accept-v2.maude:136-144`, `maude/tls-data.maude:197-208` | Fixed-DH certificate key value is modeled, but keyAgreement usage is not. |
| `5246-AUTH-09` | Implemented | `maude/api/common-aux.maude:475-481`, `maude/api/accept-v2.maude:131-133`, `maude/rfc-requirements.maude:1364-1366` | Server certificate builder filters certificates by offered signature algorithms. |
| `5246-AUTH-10` | Implemented | `maude/api/accept-v2.maude:210-216`, `maude/rfc-requirements.maude:1401-1405`, `maude/rfc-requirements.maude:1729-1734` | DHE/ECDHE ServerKeyExchange signature covers both randoms and params. |
| `5246-AUTH-11` | Partial | `maude/api/accept-v2.maude:200-204`, `maude/rfc-requirements.maude:1736-1741` | Algorithm choice exists, but certificate/key compatibility is not fully wired on receive. |
| `5246-AUTH-12` | Implemented | `maude/api/accept-v2.maude:232-256`, `maude/api/connect-v2.maude:184-187` | Anonymous cipher suites skip CertificateRequest. |
| `5246-AUTH-13` | Implemented | `maude/api/connect-v2.maude:238-257` | Requested client Certificate is always sent; unsuitable certificates produce an empty list. |
| `5246-AUTH-14` | Partial | `maude/api/connect-v2.maude:259-273`, `maude/rfc-requirements.maude:1622-1624` | Client certificate selection matches request fields; suite/extension receive validation is incomplete. |
| `5246-AUTH-15` | Implemented | `maude/api/connect-v2.maude:259-273` | Client certificate selection checks requested certificate type and signature algorithm. |
| `5246-AUTH-16` | Implemented | `maude/api/connect-v2.maude:259-265`, `maude/rfc-requirements.maude:1377-1380` | Client certificate signature algorithm must occur in the requested list. |
| `5246-AUTH-17` | Partial | `maude/api/connect-v2.maude:344-355`, `maude/rfc-requirements.maude:1664-1692` | CertificateVerify uses requested algorithm and has validation equations, but receive-side state/key wiring is incomplete. |
| `8446-AUTH-01` | Implemented | `maude/rfc-requirements.maude:643-650`, `maude/rfc-requirements.maude:685-694` | Certificate-auth ClientHello requires `signature_algorithms`. |
| `8446-AUTH-02` | Partial | `maude/rfc-requirements.maude:669-683`, `maude/rfc-requirements.maude:1119-1121` | ClientHello rejects MD5/SHA-224/DSA offers; CertificateVerify use checks only SHA-1, so deprecated-use coverage is incomplete. |
| `8446-AUTH-03` | Implemented | `maude/rfc-requirements.maude:407-410`, `maude/rfc-requirements.maude:1050-1052` | Receivers reject SHA-1/MD5 certificate signatures. |
| `8446-AUTH-04` | Implemented | `maude/rfc-requirements.maude:397-399`, `maude/rfc-requirements.maude:976-978` | CertificateRequest must include `signature_algorithms`. |
| `8446-AUTH-05` | Implemented | `maude/api/accept-v3.maude:235-237`, `maude/api/connect-v3.maude:290-292` | PSK-authentication skips main-handshake CertificateRequest. |
| `8446-AUTH-06` | Implemented | `maude/api/accept-v3.maude:271-285` | Server Certificate is built on cert-auth path and skipped only for PSK. |
| `8446-AUTH-07` | Partial | `maude/api/connect-v3.maude:416-432`, `maude/rfc-requirements.maude:1027-1029` | Certificate-if-requested is modeled, but empty-client-certificate behavior is not RFC-compatible. |
| `8446-AUTH-08` | Partial | `maude/api/common-aux.maude:455-457` | Processing assumes the first certificate supplies the peer key; no chain-order validation checks sender/end-entity-first. |
| `8446-AUTH-09` | Implemented | `maude/rfc-requirements.maude:1058-1060`, `maude/api/connect-v3.maude:327-341` | Server `certificate_list` non-empty check is invoked by server-certificate processing. |
| `8446-AUTH-10` | Implemented | `maude/tls-data.maude:194-195` | Certificate sort only has `x509`; alternate TLS 1.3 certificate types are not modeled. |
| `8446-AUTH-11` | Partial | `maude/rfc-requirements.maude:421-424`, `maude/rfc-requirements.maude:445-451` | Public-key/signature-algorithm compatibility is checked abstractly, but certificate restrictions/key usage are not modeled. |
| `8446-AUTH-12` | Not implemented | `maude/tls-data.maude:197-208` | No key-usage or `digitalSignature` certificate field exists. |
| `8446-AUTH-13` | Partial | `maude/rfc-requirements.maude:421-431`, `maude/rfc-requirements.maude:407-410` | Certificate signature algorithm acceptability and SHA-1/MD5 rejection exist, but full chain/fallback behavior is not modeled. |
| `8446-AUTH-14` | Implemented | `maude/rfc-requirements.maude:1046-1056`, `maude/api/accept-v3.maude:365-380` | Client certificate signature acceptability and signature validity are checked on server receive. |
| `8446-AUTH-15` | Not implemented | `maude/tls-data.maude:273-326` | No `oid_filters` extension/field is represented. |
| `8446-AUTH-16` | Implemented | `maude/api/connect-v3.maude:452-491`, `maude/api/accept-v3.maude:304-337`, `maude/api/connect-v3.maude:354-356`, `maude/api/accept-v3.maude:300-302` | CertificateVerify is built/processed between Certificate and Finished on certificate-auth paths, with PSK skips. |
| `8446-AUTH-17` | Partial | `maude/rfc-requirements.maude:1087-1121` | CertificateVerify algorithm offered/requested, key-compatible, and not SHA-1 are checked; RSA-PSS is not represented. |
| `8446-AUTH-18` | Implemented | `maude/rfc-requirements.maude:441-443`, `maude/rfc-requirements.maude:1105-1110` | CertificateVerify signature is verified over the transcript hash. |
| `8446-AUTH-19` | Implemented | `maude/api/accept-v3.maude:235-237`, `maude/api/accept-v3.maude:271-273`, `maude/api/accept-v3.maude:300-302`, `maude/api/connect-v3.maude:321-323`, `maude/api/connect-v3.maude:354-356` | PSK path skips certificate authentication messages. |

### Cryptographic-Context Validation (`M_ctx = 7 / N_ctx = 15`)

| ID | Status | Maude evidence | Assessment |
|---|---|---|---|
| `5246-CTX-01` | Implemented | `maude/api/connect-v2.maude:367-420`, `maude/api/accept-v2.maude:400-455` | CCS moves pending read/write keys into active session keys. |
| `5246-CTX-02` | Implemented | `maude/api/connect-v2.maude:390-400`, `maude/api/accept-v2.maude:474-486`, `maude/api/common-aux.maude:430-432` | Finished after CCS is encrypted with the active write key. |
| `5246-CTX-03` | Not implemented | `maude/tls-data.maude:10-15` | HelloRequest is not modeled, so hash exclusion is absent. |
| `5246-CTX-04` | Implemented | `maude/api/connect-v2.maude:344-355`, `maude/rfc-requirements.maude:1690-1692` | CertificateVerify signs the prior transcript before adding itself. |
| `5246-CTX-05` | Partial | `maude/api/connect-v2.maude:344-355`, `maude/rfc-requirements.maude:1387-1390`, `maude/rfc-requirements.maude:1690-1692` | Private-key proof is modeled, but server receive validation is not fully wired. |
| `5246-CTX-06` | Partial | `maude/api/connect-v2.maude:390-454`, `maude/api/accept-v2.maude:422-486`, `maude/rfc-requirements.maude:1837-1842` | Protected Finished is modeled; receive verification and app-data gating are incomplete. |
| `5246-CTX-07` | Partial | `maude/api/connect-v2.maude:398-400`, `maude/api/accept-v2.maude:484-486`, `maude/rfc-requirements.maude:1419-1420` | Finished uses master secret and suite hash, but not RFC role labels/full PRF structure. |
| `5246-CTX-08` | Implemented | `maude/api/common-aux.maude:445-446`, `maude/api/connect-v2.maude:367-420`, `maude/api/accept-v2.maude:448-486` | Transcript excludes record headers and CCS; Finished hash is computed before appending Finished. |
| `5246-CTX-09` | Partial | `maude/tls-data.maude:83-94`, `maude/api/connect-v2.maude:307-309`, `maude/api/accept-v2.maude:355-358` | Master secret derivation uses PMS and randoms; exact 48-byte PMS length is not modeled. |
| `8446-CTX-01` | Partial | `maude/api/accept-v3.maude:244-254`, `maude/api/accept-v3.maude:497-509` | Main CertificateRequest builder uses zero context and PHA uses nonce context; receiver does not validate main-handshake zero context or uniqueness. |
| `8446-CTX-02` | Implemented | `maude/api/connect-v3.maude:420-432`, `maude/rfc-requirements.maude:1038-1040`, `maude/api/accept-v3.maude:275-285` | Client Certificate echoes stored request context and server validates it; server Certificate has no request-context field. |
| `8446-CTX-03` | Partial | `maude/api/accept-v3.maude:311-312`, `maude/api/connect-v3.maude:460-462`, `maude/rfc-requirements.maude:1105-1110` | CertificateVerify signs/verifies transcript hash, but the RFC role-specific context string is not modeled. |
| `8446-CTX-04` | Implemented | `maude/rfc-requirements.maude:454-456`, `maude/rfc-requirements.maude:1150-1155`, `maude/api/accept-v3.maude:334-337`, `maude/api/connect-v3.maude:489-491` | Finished verify_data HMAC construction and receiver validation are modeled. |
| `8446-CTX-05` | Implemented | `maude/rfc-requirements.maude:521-565`, `maude/rfc-requirements.maude:577-580` | PSK binder transcript strips `pre_shared_key`, uses resumption binder key, and is validated. |
| `8446-CTX-06` | Partial | `maude/api/connect-v3.maude:81-82`, `maude/api/connect-v3.maude:98-111`, `maude/rfc-requirements.maude:532-540` | Second ClientHello binder builder/verifier include prior transcript plus truncated ClientHello, but explicit RFC message-hash HRR transcript construction is not represented. |

### Session/Resumption/Post-Handshake Validation (`M_sess = 11 / N_sess = 32`)

| ID | Status | Maude evidence | Assessment |
|---|---|---|---|
| `5246-SESS-01` | Not implemented | `maude/api/connect-v2.maude:468-474`, `maude/api/accept-v2.maude:500-506` | Fatal alerts set error state but do not invalidate cached sessions. |
| `5246-SESS-02` | Implemented | `maude/component.maude:121-137`, `maude/api/connect-v2.maude:440-448`, `maude/api/accept-v2.maude:474-482` | Session state is inserted only after Finished processing/building. |
| `5246-SESS-03` | Not implemented | `maude/api/accept-v2.maude:48-49`, `maude/api/common-aux.maude:401-408` | Resumption lookup ignores whether the original cipher suite was offered. |
| `5246-SESS-04` | Not implemented | `maude/api/common-aux.maude:401-408` | Resumption lookup ignores whether the original compression method was offered. |
| `5246-SESS-05` | Implemented | `maude/api/common-aux.maude:404-415`, `maude/api/accept-v2.maude:89-97`, `maude/api/connect-v2.maude:75-81`, `maude/scenario/rfc/5246-core.maude:687-700` | Accepted session ID is echoed and both peers go directly to CCS/Finished. |
| `5246-SESS-06` | Implemented | `maude/api/common-aux.maude:404-415`, `maude/api/accept-v2.maude:93-96` | Resumed cipher suite comes from cached session state. |
| `5246-SESS-07` | Implemented | `maude/api/common-aux.maude:402-415`, `maude/api/accept-v2.maude:89-96`, `maude/scenario/rfc/5246-core.maude:704-717` | Failed resumption falls back to a new session/full handshake. |
| `8446-SESS-01` | Partial | `maude/rfc-requirements.maude:567-574`, `maude/api/accept-v3.maude:54` | Second ClientHello check exists, but it only compares allowed extension changes, not all ClientHello fields. |
| `8446-SESS-02` | Implemented | `maude/api/connect-v3.maude:153-179`, `maude/rfc-requirements.maude:799-801` | HRR processing replaces key_share with the requested group and checks selected-group validity. |
| `8446-SESS-03` | Implemented | `maude/api/connect-v3.maude:180-191`, `maude/rfc-requirements.maude:499-501` | HRR path removes `early_data`; second-ClientHello requirements forbid it. |
| `8446-SESS-04` | Not implemented | `maude/tls-data.maude:325`, `maude/rfc-requirements.maude:291-297` | `cookie` exists as an extension/allowlisted HRR extension, but no rule copies it into the second ClientHello. |
| `8446-SESS-05` | Partial | `maude/api/connect-v3.maude:81-82`, `maude/api/connect-v3.maude:109`, `maude/tls-data.maude:307` | Second-ClientHello PSK binders are recomputed with HRR transcript, but ticket age and incompatible PSK dropping are not modeled. |
| `8446-SESS-06` | Implemented | `maude/rfc-requirements.maude:613-618`, `maude/api/connect-v3.maude:126-132` | `early_data` in ClientHello requires `pre_shared_key`, and early-data build requires PSK info. |
| `8446-SESS-07` | Implemented | `maude/api/connect-v3.maude:126-132`, `maude/api/accept-v3.maude:90-96` | Early data uses the first PSK entry and the server chooses the first offered ticket identity for early secret. |
| `8446-SESS-08` | Not implemented | `maude/tls-message.maude:80`, `maude/api/accept-v3.maude:480` | Ticket age is not modeled; NewSessionTicket content is only ticket id plus nonce. |
| `8446-SESS-09` | Partial | `maude/api/accept-v3.maude:77-80`, `maude/api/accept-v3.maude:111-115` | Early-data state exists, but age/version/ALPN/cipher-suite acceptance checks are not modeled. |
| `8446-SESS-10` | Not implemented | `maude/api/accept-v3.maude:77-80` | There is no rejection/discard path for failed early-data checks; server enters early-data state solely on the extension. |
| `8446-SESS-11` | Partial | `maude/component.maude:65`, `maude/ciphersuite.maude:698`, `maude/api/accept-v3.maude:48-49` | PSKInfo stores cipher suite and hashes are known, but server cipher selection is independent of PSK hash. |
| `8446-SESS-12` | Partial | `maude/rfc-requirements.maude:848-854` | Selected PSK range and key_share/PSK mode checks exist, but PSK hash/cipher match and early-data identity-0 check are incomplete. |
| `8446-SESS-13` | Not implemented | `maude/tls-data.maude:10-16`, `maude/tls-message.maude:80` | `EndOfEarlyData` is absent from handshake types and message constructors. |
| `8446-SESS-14` | Not implemented | `maude/tls-data.maude:10-16`, `maude/tls-message.maude:80` | Same `EndOfEarlyData` absence; no sender-side EndOfEarlyData rule exists. |
| `8446-SESS-15` | Not implemented | `maude/tls-data.maude:10-16`, `maude/tls-message.maude:80` | Same `EndOfEarlyData` absence; no client abort rule for received EndOfEarlyData exists. |
| `8446-SESS-16` | Partial | `maude/api/accept-v3.maude:473-482`, `maude/api/connect-v3.maude:514-520` | Tickets store original cipher suite and PSK, but resumption does not enforce same KDF hash. |
| `8446-SESS-17` | Not implemented | `maude/tls-data.maude:289` | No SNI/server_name model exists in extension constructors. |
| `8446-SESS-18` | Not implemented | `maude/tls-message.maude:80` | No lifetime/time fields exist in NewSessionTicket syntax. |
| `8446-SESS-19` | Not implemented | `maude/api/accept-v3.maude:480` | No `ticket_age_add`; NewSessionTicket uses only `tkId` and nonce. |
| `8446-SESS-20` | Partial | `maude/scenario/script/initialize.maude:176`, `maude/rfc-requirements.maude:949-954`, `maude/api/accept-v3.maude:497-509` | PHA extension and client-side requirement exist, but server PHA build is not guarded by client-offered PHA. |
| `8446-SESS-21` | Partial | `maude/api/connect-v3.maude:538-552`, `maude/api/connect-v3.maude:420-432`, `maude/api/connect-v3.maude:452-481` | Authenticated PHA response path exists, but declining with empty Certificate/Finished is not modeled. |
| `8446-SESS-22` | Implemented | `maude/api/connect-v3.maude:538-552`, `maude/api/connect-v3.maude:420-432`, `maude/api/connect-v3.maude:452-481` | PHA response is forced through Certificate, CertificateVerify, Finished states. |
| `8446-SESS-23` | Implemented | `maude/rfc-requirements.maude:949-954`, `maude/rfc-requirements.maude:98` | PHA without prior extension maps to fatal `unexpected-message`. |
| `8446-SESS-24` | Implemented | `maude/api/connect-v3.maude:571-582`, `maude/api/connect-v3.maude:619-655`, `maude/api/accept-v3.maude:524-535`, `maude/api/accept-v3.maude:578-590` | KeyUpdate send/process rules advance write/read keys. |
| `8446-SESS-25` | Partial | `maude/api/connect-v3.maude:577-582`, `maude/api/connect-v3.maude:619-655`, `maude/api/accept-v3.maude:530-535`, `maude/api/accept-v3.maude:578-590` | `update_requested` response state machine exists, but general post-handshake application data/new-key acceptance is not modeled. |

## Audit Notes

- Several TLS 1.2 `rfc-requirement` equations depend on client/server object attributes, but some process calls pass empty or insufficient objects. Those rows are classified as `Partial` unless the corresponding build rule deterministically enforces the requirement.
- `MsgSize` is symbolic (`valid`), so concrete malformed byte-length and vector-bound checks are only counted when the modeled requirement is explicitly covered by `validMsgSize` and matching message constructors.
- Associative-commutative message/extension representations intentionally abstract away concrete ordering in some places. This blocks full implementation of requirements such as TLS 1.3 `pre_shared_key` being the last extension.
- Requirements for features outside the current model, including TLS 1.2 HelloRequest, TLS 1.3 EndOfEarlyData, SNI binding for tickets, ticket age, ticket lifetime, and downgrade sentinels, are marked `Not implemented`.
