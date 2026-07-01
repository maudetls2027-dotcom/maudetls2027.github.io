# RFC-Check Denominator V1

This file records the task-2 denominator for the paper's RFC-check coverage
table. It counts in-scope RFC 5246 and RFC 8446 protocol-level `MUST` /
`MUST NOT` obligations inside the Section 3 modeled TLS scope.

It does not count all normative RFC language. It excludes concrete record
protection internals, primitive crypto implementation details, TCP/I/O/timing,
deployment policy, `SHOULD`/`MAY` guidance, and requirements outside the
modeled TLS handshake/authentication/negotiation/session scope.

## Final Denominator

| RFC-check class | N |
|---|---:|
| `syntax` | 13 |
| `state` | 19 |
| `extension` | 23 |
| `negotiation` | 30 |
| `auth` | 36 |
| `ctx` | 15 |
| `sess` | 32 |
| `total` | 168 |

Use these values in the table:

```tex
N_{\mathsf{syn}} = 13
N_{\mathsf{state}} = 19
N_{\mathsf{ext}} = 23
N_{\mathsf{neg}} = 30
N_{\mathsf{auth}} = 36
N_{\mathsf{ctx}} = 15
N_{\mathsf{sess}} = 32
N_{\mathsf{total}} = 168
```

## RFC Breakdown

| RFC | syntax | state | extension | negotiation | auth | ctx | sess | total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| RFC 5246 | 8 | 7 | 6 | 13 | 17 | 9 | 7 | 67 |
| RFC 8446 | 5 | 12 | 17 | 17 | 19 | 6 | 25 | 101 |
| Total | 13 | 19 | 23 | 30 | 36 | 15 | 32 | 168 |

## Evidence Inventory

The rows below are the concrete denominator items behind the class counts.
`Source lines` point to the local RFC text files under `maude/docs/specs/tls/`.
The evidence statement is a concise restatement of the cited RFC requirement
or normative protocol-structure rule, not a long verbatim RFC quotation.

### Syntax (`N_syn = 13`)

| ID | RFC | RFC section | Source lines | Evidence statement |
|---|---|---|---|---|
| `5246-SYN-01` | 5246 | 6.2.1 Fragmentation | `rfc5246.txt:1043-1058`, `1081-1091` | TLSPlaintext framing defines type/version/length/fragment fields; plaintext length is bounded, and Handshake/Alert/CCS records cannot be zero-length. |
| `5246-SYN-02` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2247-2259`, `2315-2319` | ClientHello must match the defined field layout, with either no extension tail or a valid extension vector, and exact message length. |
| `5246-SYN-03` | 5246 | 7.4.1.3 Server Hello | `rfc5246.txt:2336-2348`, `2359-2361` | ServerHello has fixed fields plus an optional extension vector detected after `compression_method`. |
| `5246-SYN-04` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2641-2645` | Certificate carries a length-bounded vector of ASN.1 certificate entries. |
| `5246-SYN-05` | 5246 | 7.4.3 Server Key Exchange | `rfc5246.txt:2815-2825`, `2863-2882` | ServerKeyExchange body is selected by key-exchange algorithm; DH parameters are non-empty length-prefixed values, and DHE adds signed parameters. |
| `5246-SYN-06` | 5246 | 7.4.4 Certificate Request | `rfc5246.txt:2941-2954` | CertificateRequest contains bounded certificate-type, signature-algorithm, and authority-name vectors. |
| `5246-SYN-07` | 5246 | 7.4.7 Client Key Exchange | `rfc5246.txt:3199-3210`, `3345-3358`, `3367-3368`, `3390-3407` | ClientKeyExchange body is selected by key exchange; RSA premaster encoding includes length bytes, and DH public values use implicit/explicit forms. |
| `5246-SYN-08` | 5246 | 7.1 Change Cipher Spec Protocol | `rfc5246.txt:1495-1502` | ChangeCipherSpec is exactly the defined one-byte enum message. |
| `8446-SYN-01` | 8446 | 5 Record Protocol | `rfc8446.txt:4290-4294`, `4319-4322` | TLS defines record content types for processing; unexpected record types terminate with `unexpected_message`. |
| `8446-SYN-02` | 8446 | 4.1.2 Client Hello | `rfc8446.txt:1546-1553`, `1575-1587` | TLS 1.3 ClientHello uses the fixed legacy version field while actual versions are carried in `supported_versions`. |
| `8446-SYN-03` | 8446 | 4.1.3 Server Hello | `rfc8446.txt:1693-1711` | TLS 1.3 ServerHello uses the defined structure with fixed legacy version field value. |
| `8446-SYN-04` | 8446 | 5 Record Protocol | `rfc8446.txt:4296-4310` | Compatibility CCS is accepted only as an unprotected single-byte `0x01` record in the allowed handshake window; other CCS forms abort. |
| `8446-SYN-05` | 8446 | 4.6.3 Key and IV Update | `rfc8446.txt:4237-4248` | `KeyUpdate.request_update` must be one of the defined enum values; any other value terminates with `illegal_parameter`. |

### Message Order Expectation (`N_state = 19`)

| ID | RFC | RFC section | Source lines | Evidence statement |
|---|---|---|---|---|
| `5246-STA-01` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2150-2154` | Initial connection starts with ClientHello; later ClientHello can answer HelloRequest or initiate renegotiation. |
| `5246-STA-02` | 5246 | 7.4 Handshake Protocol | `rfc5246.txt:2079-2088` | Handshake messages must be sent in the specified order; unexpected order is fatal. |
| `5246-STA-03` | 5246 | 7.4.3 Server Key Exchange | `rfc5246.txt:2771-2777` | ServerKeyExchange, when used, follows server Certificate, or ServerHello in anonymous negotiation. |
| `5246-STA-04` | 5246 | 7.4.4 Certificate Request | `rfc5246.txt:2931-2937` | CertificateRequest, when sent, follows ServerKeyExchange or the server Certificate. |
| `5246-STA-05` | 5246 | 7.4.7 Client Key Exchange | `rfc5246.txt:3154-3159` | ClientKeyExchange always occurs; it follows client Certificate if present, otherwise it is first after ServerHelloDone. |
| `5246-STA-06` | 5246 | 7.4.8 Certificate Verify | `rfc5246.txt:3425-3432` | CertificateVerify, when sent, immediately follows ClientKeyExchange. |
| `5246-STA-07` | 5246 | 7.4.9 Finished | `rfc5246.txt:3481-3487`, `3543-3544` | Finished is sent immediately after CCS and is fatal if CCS did not occur at the proper point. |
| `8446-STA-01` | 8446 | 4 Handshake Protocol | `rfc8446.txt:1383-1386` | Handshake messages must follow the specified order; unexpected order aborts. |
| `8446-STA-02` | 8446 | 4.1.2 Client Hello | `rfc8446.txt:1487-1491`, `1530-1537` | ClientHello is first except on the HRR retry path; post-TLS-1.3 ClientHello and TLS 1.3 renegotiation are rejected. |
| `8446-STA-03` | 8446 | 4.1.4 Hello Retry Request | `rfc8446.txt:1831-1840` | A second HelloRetryRequest in the same connection aborts. |
| `8446-STA-04` | 8446 | 4.3.1 Encrypted Extensions | `rfc8446.txt:3313-3316` | Server sends EncryptedExtensions immediately after ServerHello. |
| `8446-STA-05` | 8446 | 4.3.2 Certificate Request | `rfc8446.txt:3336-3338` | CertificateRequest, if sent, follows EncryptedExtensions. |
| `8446-STA-06` | 8446 | 4.4 Authentication Messages | `rfc8446.txt:3400-3409` | Certificate, CertificateVerify, and Finished are the final authentication-flight messages; Finished is always in the block. |
| `8446-STA-07` | 8446 | 4.4.3 Certificate Verify | `rfc8446.txt:3825-3833` | CertificateVerify, when sent, is immediately after Certificate and immediately before Finished. |
| `8446-STA-08` | 8446 | 4.4.2 Certificate | `rfc8446.txt:3544-3550` | Client Certificate is sent iff requested; if no certificate is available, an empty Certificate is still followed by Finished. |
| `8446-STA-09` | 8446 | 2 Protocol Overview; 4.4.4 Finished | `rfc8446.txt:704-712`, `3955-3966` | Ordinary Application Data waits until Finished has been sent and peer Finished validated, except specified early/server-flight cases. |
| `8446-STA-10` | 8446 | 4.5 End of Early Data | `rfc8446.txt:4025-4030`, `4039-4041` | EndOfEarlyData is sent only by the client, after server Finished, and only when early data was accepted. |
| `8446-STA-11` | 8446 | 4.6.2 Post-Handshake Authentication | `rfc8446.txt:4193-4199`, `4207-4214` | PHA client response messages must be consecutive; unoffered post-handshake CertificateRequest gets `unexpected_message`. |
| `8446-STA-12` | 8446 | 4.6.3 Key and IV Update | `rfc8446.txt:4227-4231` | KeyUpdate received before Finished terminates with `unexpected_message`. |

### Extension Validity (`N_ext = 23`)

| ID | RFC | RFC section | Source lines | Evidence statement |
|---|---|---|---|---|
| `5246-EXT-01` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2261-2267`, `2313-2319` | Servers must accept ClientHello with or without the extension field and reject malformed extension-tail lengths. |
| `5246-EXT-02` | 5246 | 7.4.1.4 Hello Extensions | `rfc5246.txt:2439-2443` | ServerHello cannot contain an extension type absent from the corresponding ClientHello; clients abort on unsolicited extensions. |
| `5246-EXT-03` | 5246 | 7.4.1.4 Hello Extensions | `rfc5246.txt:2453-2456` | A ClientHello or ServerHello extension list cannot contain duplicate extension types. |
| `5246-EXT-04` | 5246 | 7.4.1.4.1 Signature Algorithms | `rfc5246.txt:2558-2564` | The `anonymous` signature value is not valid inside `signature_algorithms`. |
| `5246-EXT-05` | 5246 | 7.4.1.4.1 Signature Algorithms | `rfc5246.txt:2569-2574`, `2583-2584` | A client that wants non-default acceptable signature/hash pairs must send `signature_algorithms`. |
| `5246-EXT-06` | 5246 | 7.4.1.4.1 Signature Algorithms | `rfc5246.txt:2603-2609` | Clients cannot offer this extension for pre-1.2 versions, and servers cannot send it. |
| `8446-EXT-01` | 8446 | 4.1.2; 9.3 | `rfc8446.txt:1643-1648`, `5838-5839` | Servers ignore unrecognized ClientHello extensions. |
| `8446-EXT-02` | 8446 | 4.3.2; 4.6.1; 9.3 | `rfc8446.txt:3381-3383`, `4155-4157`, `5841-5842` | Clients ignore unrecognized CertificateRequest and NewSessionTicket extensions. |
| `8446-EXT-03` | 8446 | 4.2 Extensions | `rfc8446.txt:1977-1992` | Extension responses are not sent unless the peer requested them, except HRR cookie; receipt aborts. |
| `8446-EXT-04` | 8446 | 4.2 Extensions | `rfc8446.txt:1994-2001`, `2023-2069` | Recognized extensions appearing in disallowed messages abort. |
| `8446-EXT-05` | 8446 | 4.2 Extensions | `rfc8446.txt:2079-2084` | No extension block may contain duplicate extension types. |
| `8446-EXT-06` | 8446 | 4.2; 4.2.11 | `rfc8446.txt:2079-2084`, `3204-3207` | `pre_shared_key` must be last in ClientHello; servers check and fail otherwise. |
| `8446-EXT-07` | 8446 | 4.2.1; 9.2 | `rfc8446.txt:2151-2155`, `2176-2181`, `5743-5744` | `supported_versions` is required for TLS 1.3 ClientHello, ServerHello, and HRR use. |
| `8446-EXT-08` | 8446 | 4.1.4 Hello Retry Request | `rfc8446.txt:1823-1829`, `1855-1863` | HRR must contain `supported_versions` and only the defined HRR extensions, with cookie as the request exception. |
| `8446-EXT-09` | 8446 | 4.2.3; 4.3.2; 9.2 | `rfc8446.txt:2259-2264`, `3379-3383`, `5746` | Certificate authentication requires `signature_algorithms`; CertificateRequest must include it. |
| `8446-EXT-10` | 8446 | 9.2 | `rfc8446.txt:5748-5749`, `5775-5790` | DHE/ECDHE ClientHello use requires `supported_groups`; nonconforming TLS 1.3 ClientHello aborts. |
| `8446-EXT-11` | 8446 | 9.2 | `rfc8446.txt:5751`, `5784-5790` | `supported_groups` and `key_share` must appear together for TLS 1.3 key-share use. |
| `8446-EXT-12` | 8446 | 9.2 | `rfc8446.txt:5753` | `pre_shared_key` is required for PSK key agreement. |
| `8446-EXT-13` | 8446 | 4.2.9; 9.2 | `rfc8446.txt:2849-2853`, `2863-2867`, `5755` | A client offering `pre_shared_key` must also send `psk_key_exchange_modes`; otherwise the server aborts. |
| `8446-EXT-14` | 8446 | 4.2.9 | `rfc8446.txt:2873` | The server must not send `psk_key_exchange_modes`. |
| `8446-EXT-15` | 8446 | 4.2.10 Early Data | `rfc8446.txt:2895-2898` | A client using early data must supply both `pre_shared_key` and `early_data`. |
| `8446-EXT-16` | 8446 | 4.2.6 Post-Handshake Client Authentication | `rfc8446.txt:2585-2589` | Server must not send PHA CertificateRequest to clients lacking `post_handshake_auth`, and must not send that extension itself. |
| `8446-EXT-17` | 8446 | 4.3.1 Encrypted Extensions | `rfc8446.txt:3318-3323` | Client checks EncryptedExtensions for forbidden extensions and aborts if present. |

### Negotiation Consistency (`N_neg = 30`)

| ID | RFC | RFC section | Source lines | Evidence statement |
|---|---|---|---|---|
| `5246-NEG-01` | 5246 | Appendix E.1 Compatibility | `rfc5246.txt:4860-4862` | Client rejects a server-selected protocol version it does not support or accept. |
| `5246-NEG-02` | 5246 | Appendix E.1 Compatibility | `rfc5246.txt:4864-4867` | A server seeing a higher-than-supported ClientHello version replies with its highest supported version. |
| `5246-NEG-03` | 5246 | Appendix E.1 Compatibility | `rfc5246.txt:4879-4884` | If the server has no acceptable version at or below ClientHello.client_version, it sends `protocol_version` and closes. |
| `5246-NEG-04` | 5246 | Appendix E.1 Compatibility | `rfc5246.txt:4899-4904` | Before ServerHello, compliant servers accept any `{03,XX}` record-layer version on ClientHello. |
| `5246-NEG-05` | 5246 | 7.4.7.1 RSA PMS | `rfc5246.txt:3263-3269` | RSA clients send the ClientHello version in PreMasterSecret; servers check it for TLS 1.1-or-newer ClientHello. |
| `5246-NEG-06` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2213-2223` | Server ignores unrecognized, unsupported, or unwanted cipher suites and processes the rest. |
| `5246-NEG-07` | 5246 | 7.4.1.3 Server Hello | `rfc5246.txt:2392-2395` | ServerHello selects one cipher suite from the ClientHello list, or the resumed-session value. |
| `5246-NEG-08` | 5246 | A.5 Cipher Suite | `rfc5246.txt:4156-4162` | `TLS_NULL_WITH_NULL_NULL` is only the initial state and must not be negotiated. |
| `5246-NEG-09` | 5246 | A.5 Cipher Suite | `rfc5246.txt:4228-4238` | Anonymous DH cipher suites are forbidden unless the application explicitly allows anonymous exchange. |
| `5246-NEG-10` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2291-2295`, `2303-2305` | Client compression methods must include `CompressionMethod.null`, which all implementations support. |
| `5246-NEG-11` | 5246 | 7.4.1.3 Server Hello | `rfc5246.txt:2397-2400` | ServerHello selects one compression method from the client list, or the resumed-session value. |
| `5246-NEG-12` | 5246 | 7.4.1.4.1 Signature Algorithms | `rfc5246.txt:2586-2595` | If `signature_algorithms` is absent, server uses the RFC default signature/hash pair for the negotiated key exchange. |
| `5246-NEG-13` | 5246 | 7.4.3 Server Key Exchange | `rfc5246.txt:2891-2898` | When the client offered signature algorithms, the server checks candidate cipher suites against that extension before selection. |
| `8446-NEG-01` | 8446 | 4.2.1 Supported Versions | `rfc8446.txt:2164-2169` | With `supported_versions`, server ignores ClientHello legacy version, selects only offered versions, and ignores unknown versions. |
| `8446-NEG-02` | 8446 | 4.2.1; D.2 | `rfc8446.txt:2157-2162`, `7765-7776` | Without `supported_versions`, server falls back to TLS 1.2-or-prior rules or aborts if no compatible version exists. |
| `8446-NEG-03` | 8446 | 4.2.1 Supported Versions | `rfc8446.txt:2176-2183`, `2191-2198` | TLS 1.3 ServerHello selects via `supported_versions`; client ignores legacy version and aborts unoffered/prior selections. |
| `8446-NEG-04` | 8446 | D.1 Older Server | `rfc8446.txt:7751-7753` | Client aborts if the older server-selected version is unsupported or unacceptable. |
| `8446-NEG-05` | 8446 | 4.1.3 Server Hello | `rfc8446.txt:1765-1786` | TLS 1.3 downgrade sentinels are set by servers negotiating older TLS and checked by TLS 1.3 clients. |
| `8446-NEG-06` | 8446 | 4.1.2; 9.3 | `rfc8446.txt:1608-1610`, `5838-5839` | Server ignores unrecognized or unsupported cipher suites and processes the remaining list. |
| `8446-NEG-07` | 8446 | 4.1.3; 4.1.4 | `rfc8446.txt:1728-1731`, `1865-1872` | ServerHello/HRR cipher suite must have been offered; post-HRR ServerHello keeps the HRR cipher suite. |
| `8446-NEG-08` | 8446 | B.4 Cipher Suites | `rfc8446.txt:7461-7465` | TLS 1.3 cipher suites cannot be used with TLS 1.2, and older suites cannot be used with TLS 1.3. |
| `8446-NEG-09` | 8446 | 4.1.2; 4.1.3 | `rfc8446.txt:1631-1641`, `1733-1734` | TLS 1.3 compression negotiation is fixed to null/no-compression. |
| `8446-NEG-10` | 8446 | 4.1.1 Cryptographic Negotiation | `rfc8446.txt:1430-1437` | Without PSK, no overlap in supported groups requires abort. |
| `8446-NEG-11` | 8446 | 2.1; 4.1.1 | `rfc8446.txt:737-743`, `1480-1483` | If no common cryptographic parameters can be negotiated, server aborts. |
| `8446-NEG-12` | 8446 | 4.1.1 Cryptographic Negotiation | `rfc8446.txt:1446-1448` | If selected (EC)DHE group lacks a compatible initial key_share, server sends HRR. |
| `8446-NEG-13` | 8446 | 4.2.8 Key Share | `rfc8446.txt:2705-2708` | Client KeyShareEntry values correspond to `supported_groups` and preserve order. |
| `8446-NEG-14` | 8446 | 4.2.8 Key Share | `rfc8446.txt:2714-2723` | Client does not offer duplicate key shares or key shares for groups outside `supported_groups`. |
| `8446-NEG-15` | 8446 | 4.2.8 Key Share | `rfc8446.txt:2735-2742`, `2751-2753` | HRR selected group must be supported but not already offered, and retry ClientHello uses only that group. |
| `8446-NEG-16` | 8446 | 2; 4.2.8 | `rfc8446.txt:640-643`, `2762-2776` | ServerHello key_share is exactly one selected client group and not outside client supported groups. |
| `8446-NEG-17` | 8446 | 4.1.1; 4.2.9; 4.2.11 | `rfc8446.txt:1439-1442`, `2863-2886`, `3131-3135`, `3143-3145`, `3180-3186` | PSK selection uses a client-offered mode; PSK-only forbids key_share, PSK-DHE requires it, and selected PSK/cipher hash must be compatible. |

### Authentication Validation (`N_auth = 36`)

| ID | RFC | RFC section | Source lines | Evidence statement |
|---|---|---|---|---|
| `5246-AUTH-01` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2617-2623` | Server sends Certificate for certificate-authenticated key exchange, excluding DH_anon. |
| `5246-AUTH-02` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2629-2630` | Server certificate must fit the negotiated cipher suite and negotiated extensions. |
| `5246-AUTH-03` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2647-2655` | Certificate list starts with sender certificate, and each following certificate certifies the prior one. |
| `5246-AUTH-04` | 5246 | 7.4.2; 7.4.6 Certificates | `rfc5246.txt:2667-2670`, `3097-3100` | Server and client certificate type is X.509v3 unless another type is explicitly negotiated. |
| `5246-AUTH-05` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2676-2681` | RSA key-exchange certificates must permit encryption; keyEncipherment is required if key usage is present. |
| `5246-AUTH-06` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2695-2700` | DHE_RSA server certificates must permit signing with the ServerKeyExchange signature/hash algorithm. |
| `5246-AUTH-07` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2703-2706` | DHE_DSS server certificates must permit signing with the ServerKeyExchange hash algorithm. |
| `5246-AUTH-08` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2708-2710` | Fixed-DH server certificates require keyAgreement if key usage is present. |
| `5246-AUTH-09` | 5246 | 7.4.2 Server Certificate | `rfc5246.txt:2726-2738` | If client sent `signature_algorithms`, all server certificates use a listed hash/signature pair. |
| `5246-AUTH-10` | 5246 | 7.4.3 Server Key Exchange | `rfc5246.txt:2863-2874`, `2887-2889` | Non-anonymous DHE ServerKeyExchange signs client random, server random, and DH parameters. |
| `5246-AUTH-11` | 5246 | 7.4.3 Server Key Exchange | `rfc5246.txt:2901-2904` | ServerKeyExchange signature/hash algorithms must be compatible with the server end-entity certificate key. |
| `5246-AUTH-12` | 5246 | 7.4.4 Certificate Request | `rfc5246.txt:3031-3032` | Anonymous servers cannot request client authentication; doing so is fatal. |
| `5246-AUTH-13` | 5246 | 7.3; 7.4.6 Client Certificate | `rfc5246.txt:1927-1929`, `3060-3065` | If CertificateRequest was sent, client sends Certificate; without a suitable cert, it sends an empty certificate list. |
| `5246-AUTH-14` | 5246 | 7.4.6 Client Certificate | `rfc5246.txt:3093-3095` | Client certificate must fit the negotiated cipher suite and extensions. |
| `5246-AUTH-15` | 5246 | 7.4.4; 7.4.6 Client Certificate | `rfc5246.txt:2999-3002`, `3102-3116`, `3125-3126` | Client end-entity key must match requested certificate types; signing keys must be usable with a requested signature/hash pair. |
| `5246-AUTH-16` | 5246 | 7.4.4; 7.4.6 Client Certificate | `rfc5246.txt:2995-2997`, `3143-3146` | Client certificate signatures must use acceptable hash/signature pairs from CertificateRequest. |
| `5246-AUTH-17` | 5246 | 7.4.8 Certificate Verify | `rfc5246.txt:3453-3458` | CertificateVerify signature algorithms must be listed in CertificateRequest and compatible with the client certificate key. |
| `8446-AUTH-01` | 8446 | 4.2.3 Signature Algorithms | `rfc8446.txt:2259-2264` | Certificate-auth clients must send `signature_algorithms`; a cert-auth server aborts if it is absent. |
| `8446-AUTH-02` | 8446 | 4.2.3 Signature Algorithms | `rfc8446.txt:2448-2451` | Deprecated MD5/SHA-224/DSA signature algorithms must not be offered, negotiated, or used. |
| `8446-AUTH-03` | 8446 | 4.2.3 Signature Algorithms | `rfc8446.txt:2427-2429` | TLS 1.3 servers must not offer SHA-1-signed certificates unless no valid non-SHA-1 chain exists. |
| `8446-AUTH-04` | 8446 | 4.3.2 Certificate Request | `rfc8446.txt:3379-3382` | `CertificateRequest` must include `signature_algorithms`. |
| `8446-AUTH-05` | 8446 | 4.3.2 Certificate Request | `rfc8446.txt:3392-3396` | A PSK-authenticating server must not send main-handshake `CertificateRequest`. |
| `8446-AUTH-06` | 8446 | 4.4.2 Certificate | `rfc8446.txt:3539-3542` | Server must send `Certificate` whenever certificate authentication is used. |
| `8446-AUTH-07` | 8446 | 4.4.2 Certificate | `rfc8446.txt:3544-3550` | Client sends `Certificate` iff requested; if no suitable cert, it sends an empty list and still sends Finished. |
| `8446-AUTH-08` | 8446 | 4.4.2 Certificate | `rfc8446.txt:3611-3616`, `3629-3632` | Sender/end-entity certificate must be first in the certificate list. |
| `8446-AUTH-09` | 8446 | 4.4.2 Certificate | `rfc8446.txt:3649-3652`, `3787-3788` | Server certificate list must be non-empty; client aborts on empty server Certificate. |
| `8446-AUTH-10` | 8446 | 4.4.2.2; 4.4.2.3 Certificate Selection | `rfc8446.txt:3705-3708`, `3761-3764` | Server/client certificate type must be X.509v3 unless another type was negotiated. |
| `8446-AUTH-11` | 8446 | 4.4.2.2 Server Certificate Selection | `rfc8446.txt:3710-3713` | Server end-entity public key and restrictions must match the selected authentication algorithm. |
| `8446-AUTH-12` | 8446 | 4.4.2.2 Server Certificate Selection | `rfc8446.txt:3715-3719` | Certificate must allow signing, including `digitalSignature` if Key Usage is present. |
| `8446-AUTH-13` | 8446 | 4.4.2.2 Server Certificate Selection | `rfc8446.txt:3726-3738` | Server chain must use client-advertised signature algorithms if possible; SHA-1 fallback must be client-permitted. |
| `8446-AUTH-14` | 8446 | 4.4.2.3 Client Certificate Selection | `rfc8446.txt:3771-3773` | Client certificates must be signed with acceptable signature algorithms. |
| `8446-AUTH-15` | 8446 | 4.4.2.3 Client Certificate Selection | `rfc8446.txt:3776-3779` | Client end-entity certificate must match recognized non-empty OID filters from CertificateRequest. |
| `8446-AUTH-16` | 8446 | 4.4.3 Certificate Verify | `rfc8446.txt:3825-3833` | Cert-auth endpoints must send CertificateVerify; it sits between Certificate and Finished. |
| `8446-AUTH-17` | 8446 | 4.4.3 Certificate Verify | `rfc8446.txt:3902-3916` | CertificateVerify algorithm must be offered/requested, key-compatible, RSA-PSS for RSA, and not SHA-1. |
| `8446-AUTH-18` | 8446 | 4.4.3 Certificate Verify | `rfc8446.txt:3931-3943` | Receiver must verify the CertificateVerify signature and abort on failure. |
| `8446-AUTH-19` | 8446 | Appendix E.1 Handshake | `rfc8446.txt:8034-8047` | External PSKs must not be combined with certificate authentication unless an extension negotiates it. |

### Cryptographic-Context Validation (`N_ctx = 15`)

| ID | RFC | RFC section | Source lines | Evidence statement |
|---|---|---|---|---|
| `5246-CTX-01` | 5246 | 7.1 Change Cipher Spec | `rfc5246.txt:1504-1510` | Receiving CCS activates pending read state; sending CCS activates pending write state immediately after sending. |
| `5246-CTX-02` | 5246 | 7.1 Change Cipher Spec | `rfc5246.txt:1523-1527` | After CCS is sent, the new CipherSpec must be used. |
| `5246-CTX-03` | 5246 | 7.4.1.1 Hello Request; 7.4.9 Finished | `rfc5246.txt:2142-2144`, `3554-3557` | HelloRequest is excluded from handshake hashes used by Finished and CertificateVerify. |
| `5246-CTX-04` | 5246 | 7.4.8 Certificate Verify | `rfc5246.txt:3435-3448` | CertificateVerify signs all prior handshake messages from ClientHello up to but excluding CertificateVerify, including handshake headers. |
| `5246-CTX-05` | 5246 | 7.3; 7.4.8 Certificate Verify | `rfc5246.txt:1928-1934`, `3427-3431` | CertificateVerify explicitly proves possession of the private key for a signing-capable client certificate. |
| `5246-CTX-06` | 5246 | 7.4.9 Finished | `rfc5246.txt:3491-3496` | Finished is first protected under negotiated keys; recipients must verify its contents before application data. |
| `5246-CTX-07` | 5246 | 7.4.9 Finished | `rfc5246.txt:3500-3516` | Finished verify_data is PRF over master secret, role label, and handshake hash; PRF hash must match cipher-suite rules. |
| `5246-CTX-08` | 5246 | 7.4.9 Finished | `rfc5246.txt:3535-3541`, `3546-3557` | Finished transcript includes handshake-layer data up to the current Finished, excludes record headers, CCS, alerts, and HelloRequest. |
| `5246-CTX-09` | 5246 | 8.1 Computing the Master Secret | `rfc5246.txt:3572-3582` | Master secret is derived from the pre-master secret plus ClientHello.random and ServerHello.random, and is exactly 48 bytes. |
| `8446-CTX-01` | 8446 | 4.3.2 Certificate Request | `rfc8446.txt:3367-3373` | Certificate request context must be connection-unique and zero-length except for PHA. |
| `8446-CTX-02` | 8446 | 4.4.2 Certificate | `rfc8446.txt:3591-3594` | Certificate echoes the request context; server-auth Certificate uses zero-length context. |
| `8446-CTX-03` | 8446 | 4.4.3 Certificate Verify | `rfc8446.txt:3842-3858`, `3877-3881` | CertificateVerify signs the transcript hash plus role-specific context string. |
| `8446-CTX-04` | 8446 | 4.4.4 Finished | `rfc8446.txt:3951-3953`, `3983-4007` | Finished verify_data is HMAC over the proper transcript using the derived Finished key; recipient verifies it. |
| `8446-CTX-05` | 8446 | 4.2.11; 4.2.11.2 PSK Binder | `rfc8446.txt:3170-3173`, `3227-3242` | Server must validate the selected PSK binder; the binder covers truncated ClientHello and uses `binder_key`. |
| `8446-CTX-06` | 8446 | 4.2.11.2 PSK Binder | `rfc8446.txt:3255-3275` | With HRR, binder transcript includes ClientHello1, HRR, and truncated ClientHello2 using message-hash handling. |

### Session/Resumption/Post-Handshake Validation (`N_sess = 32`)

| ID | RFC | RFC section | Source lines | Evidence statement |
|---|---|---|---|---|
| `5246-SESS-01` | 5246 | 7.2 Alert Protocol | `rfc5246.txt:1541-1543`, `1643-1646` | Fatal alerts invalidate session identifiers; failed connections must not be resumed. |
| `5246-SESS-02` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2179-2183`, `2191-2200` | SessionID identifies reusable parameters and becomes valid only after Finished completes the negotiating handshake. |
| `5246-SESS-03` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2284-2289` | A resumption ClientHello must include at least the original session cipher suite. |
| `5246-SESS-04` | 5246 | 7.4.1.2 Client Hello | `rfc5246.txt:2291-2295` | A resumption ClientHello must include the original session compression method. |
| `5246-SESS-05` | 5246 | 7.3; 7.4.1.3 Server Hello | `rfc5246.txt:1997-2003`, `2373-2381` | If the server accepts the SessionID match, it returns the same ID and both peers go directly through CCS to Finished. |
| `5246-SESS-06` | 5246 | 7.4.1.3 Server Hello | `rfc5246.txt:2383-2386` | A resumed session uses the same cipher suite originally negotiated. |
| `5246-SESS-07` | 5246 | 7.3; 7.4.1.3 Server Hello | `rfc5246.txt:2005-2007`, `2387-2390` | If resumption is not accepted, the server uses a new session ID/full handshake; clients must tolerate full negotiation. |
| `8446-SESS-01` | 8446 | 4.1.2 Client Hello | `rfc8446.txt:1490-1492`, `1524-1528` | Second ClientHello after HRR must be unchanged except for permitted edits. |
| `8446-SESS-02` | 8446 | 4.1.2 Client Hello | `rfc8446.txt:1493-1495` | If HRR requests key_share, the client replaces shares with one entry for that group. |
| `8446-SESS-03` | 8446 | 4.1.2; 4.2.10 Early Data | `rfc8446.txt:1497-1498`, `2986-2988` | Client must remove `early_data` after HRR and not include it in the follow-up ClientHello. |
| `8446-SESS-04` | 8446 | 4.1.2; 4.2.2 Cookie | `rfc8446.txt:1500-1501`, `2223-2226` | Client copies the HRR cookie into the new ClientHello and must not reuse cookies in later initial hellos. |
| `8446-SESS-05` | 8446 | 4.1.2 Client Hello | `rfc8446.txt:1519-1522` | HRR second ClientHello updates PSK ticket age and binders, and may drop incompatible PSKs. |
| `8446-SESS-06` | 8446 | 4.2.10 Early Data Indication | `rfc8446.txt:2895-2898` | Client sending early data must include both `pre_shared_key` and `early_data`. |
| `8446-SESS-07` | 8446 | 4.2.10 Early Data Indication | `rfc8446.txt:2932-2940` | The PSK used for early data must be the first offered PSK identity. |
| `8446-SESS-08` | 8446 | 4.2.10 Early Data Indication | `rfc8446.txt:2942-2948` | Server must validate NST ticket age before accepting 0-RTT for that PSK. |
| `8446-SESS-09` | 8446 | 4.2.10 Early Data Indication | `rfc8446.txt:3000-3017` | Accepting 0-RTT requires accepted PSK cipher suite, first key, and matching version/cipher/ALPN. |
| `8446-SESS-10` | 8446 | 4.2.10 Early Data Indication | `rfc8446.txt:3031-3034` | If early-data checks fail, the server must not send `early_data` and discards first-flight data. |
| `8446-SESS-11` | 8446 | 4.2.11 Pre-Shared Key Extension | `rfc8446.txt:3131-3135`, `3143-3145` | PSKs have an associated hash; server must select a compatible PSK and cipher suite. |
| `8446-SESS-12` | 8446 | 4.2.11 Pre-Shared Key Extension | `rfc8446.txt:3180-3186`, `3199-3202` | Client verifies selected PSK identity/cipher/key_share consistency; early-data acceptance requires identity 0. |
| `8446-SESS-13` | 8446 | 4.5 End of Early Data | `rfc8446.txt:4025-4027` | If the server accepted early data, the client must send EndOfEarlyData after server Finished. |
| `8446-SESS-14` | 8446 | 4.5 End of Early Data | `rfc8446.txt:4027-4029` | If the server did not accept early data, the client must not send EndOfEarlyData. |
| `8446-SESS-15` | 8446 | 4.5 End of Early Data | `rfc8446.txt:4039-4041` | Servers must not send EndOfEarlyData; clients abort if they receive it. |
| `8446-SESS-16` | 8446 | 4.6.1 New Session Ticket | `rfc8446.txt:4073-4074` | A ticket may only resume with a cipher suite using the same KDF hash. |
| `8446-SESS-17` | 8446 | 4.6.1 New Session Ticket | `rfc8446.txt:4076-4078` | Client resumes only when the new SNI is valid for the original server certificate. |
| `8446-SESS-18` | 8446 | 4.2.11.1; 4.6.1 Ticket Age/NST | `rfc8446.txt:3211-3213`, `4120-4123` | Client must not use/cache tickets beyond allowed lifetime; server ticket lifetime is capped at seven days. |
| `8446-SESS-19` | 8446 | 4.6.1 New Session Ticket | `rfc8446.txt:4128-4133` | Server must generate fresh `ticket_age_add` for every ticket. |
| `8446-SESS-20` | 8446 | 4.2.6; 4.6.2 PHA | `rfc8446.txt:2585-2588`, `4193-4196` | Server must not send post-handshake CertificateRequest unless the client offered PHA. |
| `8446-SESS-21` | 8446 | 4.6.2 Post-Handshake Authentication | `rfc8446.txt:4196-4199`, `4207-4208` | Client must respond to PHA; authenticating sends Certificate/CertificateVerify/Finished, declining sends empty Certificate/Finished. |
| `8446-SESS-22` | 8446 | 4.6.2 Post-Handshake Authentication | `rfc8446.txt:4207-4210` | Client PHA response messages must appear consecutively. |
| `8446-SESS-23` | 8446 | 4.6.2 Post-Handshake Authentication | `rfc8446.txt:4212-4214` | Client receiving PHA request without having offered PHA must send fatal `unexpected_message`. |
| `8446-SESS-24` | 8446 | 4.6.3 Key and IV Update | `rfc8446.txt:4232-4235` | After KeyUpdate, sender moves to next keys and receiver updates receiving keys. |
| `8446-SESS-25` | 8446 | 4.6.3 Key and IV Update | `rfc8446.txt:4250-4252`, `4277-4280` | `update_requested` requires a response before next application data; peers enforce KeyUpdate before accepting new-key messages. |

## Counting Granularity

- Count atomic obligations, not raw `MUST` string matches.
- Split compound `MUST` / `MUST NOT` statements when the parts are separately
  checkable.
- Group repeated ciphersuite- or certificate-type variants when they express
  one predicate-level requirement.
- Keep distinct protocol contexts separate when the check applies to different
  messages, endpoint roles, or session states.
- Include requirements that are in modeled scope even if the current
  `rfc-requirements.maude` label inventory does not yet have a matching label.

## Included Scope Summary

`syntax` includes parseable handshake bodies, selected vector bounds, record
content type checks that determine whether a handshake message is being
processed, `ChangeCipherSpec` syntax, TLS 1.3 legacy hello field syntax, and
`KeyUpdate.request_update` value syntax.

`state` includes handshake message order, current-state-dependent acceptance,
CertificateRequest/Certificate/CertificateVerify/Finished ordering,
EndOfEarlyData ordering, post-handshake ClientHello rejection, PHA response
message adjacency, and KeyUpdate pre-Finished rejection.

`extension` includes duplicate extensions, unsolicited responses, forbidden
message-specific extensions, required TLS 1.3 extensions, `pre_shared_key`
placement, `signature_algorithms` requirements, allowed HRR extensions, and
unknown-extension ignore behavior where it is deterministic and in scope.

`negotiation` includes version selection, cipher suite and compression
selection, TLS 1.2 and TLS 1.3 cipher-suite separation, named-group and
key-share consistency, PSK key-exchange mode and PSK/cipher consistency,
downgrade sentinel checks, and RSA premaster version checks where modeled.

`auth` includes certificate message presence, certificate list structure,
certificate-chain signature acceptability, certificate/key/ciphersuite
compatibility, key-usage/signing compatibility, CertificateRequest-driven
client certificate constraints, CertificateVerify algorithm constraints, SHA-1
and MD5 exclusions, RSA-PSS requirements, and external PSK plus certificate
authentication restrictions.

`ctx` includes CertificateVerify transcript validation, Finished transcript
and key validation, PSK binder validation including HRR transcript handling,
TLS 1.2 ChangeCipherSpec activation context, TLS 1.2 Finished hash context,
and CertificateRequest context validation.

`sess` includes TLS 1.2 session resumption behavior, TLS 1.3 HRR second
ClientHello constraints, TLS 1.3 PSK and early-data consistency checks,
NewSessionTicket resumption constraints, post-handshake authentication, and
KeyUpdate response/order checks.

## Cross-Check Against Appendix C And Current Labels

Appendix C and `rfc-requirements.maude` are useful sanity checks but should not
be used as the denominator source. They are closer to a current label inventory.

- Appendix-label count: 154.
- Current normalized label hint: 159.
- This spec-mined denominator: 168.

The denominator is larger because it includes in-scope RFC requirements that
are not yet consistently represented as current requirement labels, especially:

- TLS 1.2 session resumption requirements from RFC 5246.
- TLS 1.3 PSK/NewSessionTicket/early-data/session constraints from RFC 8446.
- TLS 1.3 `pre_shared_key` last-extension placement.
- TLS 1.3 PSK/cipher-hash consistency.
- TLS 1.3 CertificateVerify RSA-PSS and key compatibility constraints.
- TLS 1.3 CertificateRequest context uniqueness.
- TLS 1.3 downgrade sentinel checks.

Non-RFC-5246/8446 labels such as RFC 5746 `renegotiation_info` and RFC 4492
supported-groups behavior are intentionally not included in the `168` total.
They can be reported separately if the paper expands the denominator beyond
RFC 5246 and RFC 8446.

## Exclusion Notes

Excluded examples:

- Record-protection internals: CBC padding, AEAD expansion, nonce generation,
  sequence-number wrap, decryption failure mechanics, decompression internals,
  MAC timing behavior.
- Pure transport behavior: TCP close, buffering, delivery, `close_notify`
  transport requirements.
- Pure capability requirements: mandatory algorithm implementation support,
  deployment policy, application profile requirements.
- `SHOULD` / `MAY` guidance.
- SSL 2.0 compatibility ClientHello and broad legacy compatibility appendix
  requirements that are not represented in the modeled TLS feature scope.

Ambiguous items to revisit before final camera-ready text:

- Whether to count all TLS 1.3 early-data / EndOfEarlyData requirements. V1
  includes deterministic early-data and EndOfEarlyData state/session checks
  because early-data vocabulary and state transitions exist locally, but these
  may be moved out of scope if the paper wants to exclude 0-RTT behavior.
- Whether to count full certificate path/name validation beyond the abstract
  certificate-chain and signature checks represented by the model. V1 counts
  only abstract certificate constraints that map to modeled fields.
