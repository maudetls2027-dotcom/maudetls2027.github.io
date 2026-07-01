# TLS Intruder Behavior Deviation Categories

이 문서는 `/Users/gsojc234/Documents/related_works.zip`에 포함된 TLS library testing, model-based testing, fuzzing, state-learning 논문들을 기준으로 TLS protocol testing에서 가정하는 intruder behavior, 즉 message deviation category를 정리한 것이다.

세부 근거는 [evidence.md](evidence.md)에, 현재 Maude behavior deviation specification의 표현 가능성 판정 근거는 [expressibility.md](expressibility.md)에 정리했다.

## Scope

분석 대상은 TLS 구현체나 TLS library를 실제 메시지, trace, sequence, record, transport, oracle로 테스트하는 논문이다. 순수 암호 증명이나 프로토콜 설계 논문은 제외하고, TLS-Anvil, TLS-Attacker, FLEXTLS, state machine learning, DTLS fuzzing, padding/Bleichenbacher/truncation 계열 논문에서 실제로 사용한 deviation을 추출했다. X.509 certificate 내부 field/extension/chain validation은 현재 table의 category 범위에서 제외하고, TLS message 안의 certificate-list 수준 조작만 C2로 분류한다.

`Expressible`은 현재 `maude/scenario/behavior-specification-syntax.maude`와 `maude/scenario/behavior-specification-semantics.maude`의 behavior deviation DSL, 그리고 이를 여러 개 조합해 실행 경로를 관측하는 기존 `scenarioProperty` framework로 표현 가능한지를 뜻한다.

- `O`: 현재 DSL의 `setM`, `add`, `remove`, `skip()`, `setF`, `noCheck`와 action guard로 직접 표현 가능하다.
- `△`: 일부는 표현 가능하지만, 현재 DSL 바깥의 test harness, concrete byte encoder, transport/timing control이 필요하다.
- `X`: 현재 DSL의 message-level model로는 표현되지 않는다.

## Paper-Ready Category Table

일반적으로 TLS library testing 논문들은 intruder가 아래와 같은 deviation을 만들 수 있다고 가정한다. 현재 Maude behavior deviation specification은 C1-C4를 주로 다루며, C5-C6은 record-byte, transport/timing 계층이 필요하므로 대체로 비표현으로 보는 것이 타당하다.

| Category | Description | Expressible | Behavior Deviation Specification Examples | Representative References |
|---|---|---:|---|---|
| C1. Message Field/Value Modification | Handshake, alert, extension, record header의 scalar/list field 값을 바꾼다. 예: protocol version, cipher suite, named group, signature algorithm, random, session id, Finished verify data, alert description, handshake length. | O | `setM(#protocol, mv[...])`, `setM(#cipherSuites, mv[...])`, `setM(#handshakeLen, mv[...])`, `setM(#verifyData, mv[...])`, `setM(#alertDesc, mv[...])` | TLS-Anvil, Systematic Fuzzing, Exploiting Dissent, SoK |
| C2. Message Structure/Component Modification | 메시지 내부 component, extension, list를 추가, 제거, 빈 값으로 교체한다. 예: empty Certificate list, missing extension, added supported group, missing PSK extension. Concrete byte-level length inconsistency, excess/deficit data는 C5로 분류하고, X.509 certificate 내부 변형은 현재 table 범위에서 제외한다. | O | `add(#supported-groups, mv[...])`, `remove(#supported-versions)`, `setM(#certificate-list, emptyCertificateList)`, `remove(#certificate-list)`, `remove(#pre-shared-key)` | TLS-Anvil, Exploiting Dissent, Protocol State Fuzzing, OpenSSL State Machine, state-learning client-auth omission studies |
| C3. Protocol Message Flow/Ordering Modification | TLS 메시지의 순서를 바꾸거나, 필수 메시지를 생략하거나, 예상치 못한 메시지를 삽입/반복한다. 예: early CCS, skipped CertificateVerify, duplicate ClientHello, post-handshake CCS, unexpected AppData/Heartbeat/Alert. | O/△ | `skip()` on selected build/process action, scenario-level duplicate `ClientHello`, scenario-level early `ChangeCipherSpec`, `remove(#certificate-list)` plus `skip()` for auth-message omission | FLEXTLS, Protocol State Fuzzing, State Machine Inference, Planning-Based Testing, Weighted Sequence Testing |
| C4. Negotiation/Path/State Feature Modification | handshake path와 negotiation 결과를 의도적으로 비정상화한다. 예: unoffered group/signature algorithm, GREASE, invalid compression, HRR/resumption/PSK/renegotiation/key-update path, object state override. | O | `setM(#supported-versions, mv[...])`, `setM(#key-shares-groups, mv[...])`, `add(#early-data, mv[true])`, `setF(@selectedCipherSuite, av[...])`, `noCheck(label[N])`; multiple `BehaviorDVSpec` plus `scenarioProperty` for path-level cases | TLS-Anvil, Systematic Fuzzing, Internet-Based State Learning, DTLS-Fuzzer |
| C5. Concrete Byte/Cryptographic Payload Modification | TLS record fragment, concrete length inconsistency, excess/deficit bytes, raw-content mutation, record/message byte truncation, ciphertext, MAC/tag, CBC padding, RSA premaster-secret ciphertext, PRF/signature byte, encrypted application data를 byte-level로 조작하고 oracle response를 본다. | X | Not expressible for arbitrary record fragmentation, concrete record/message byte truncation, raw byte append/delete, ciphertext bit flip, CBC padding timing, AEAD tag byte mutation, concrete RSA padding oracle query. Record header field mutation belongs to C1. | TLS-Anvil, Lucky Thirteen, ROBOT, Scalable Padding Oracle Scanning, FLEXTLS |
| C6. Transport/Timing Modification | TLS message content 바깥의 transport와 timing behavior를 조작하거나 관측한다. 예: TCP close/reset, missing `close_notify`, transport/application truncation, timeout, timing side-channel, alert/TCP/timeout response classification. | X | Not expressible for TCP reset/FIN, missing `close_notify`, timeout, timing measurement, transport/application truncation, or alert/TCP/timeout oracle classification. | Towards Internet-Based State Learning, Lucky Thirteen, Scalable Padding Oracle Scanning, Truncating TLS Connections, ROBOT |

## Recommended Wording

논문 본문에는 다음과 같이 쓸 수 있다.

> Prior TLS library testing studies commonly assume an intruder that can deviate from a normal TLS trace by modifying message fields, adding or removing message components, changing protocol message order, and manipulating negotiation paths. More implementation-oriented studies additionally rely on concrete byte mutation, cryptographic payload/oracle queries, and transport/timing deviations. Our behavior deviation specification directly captures the former message-level deviations, while the latter categories require concrete-byte record, transport, or timing support outside the current message model.

한국어로 쓰면 다음과 같이 정리할 수 있다.

> 기존 TLS library testing 연구들은 일반적으로 intruder가 정상 TLS trace에서 벗어나 message field를 수정하고, message component를 추가/삭제하며, protocol message의 순서를 변경하거나 특정 메시지를 생략/반복하고, negotiation path를 조작할 수 있다고 가정한다. 반면 concrete byte, cryptographic payload/oracle, transport close/reset, timing side-channel에 의존하는 deviation은 현재의 message-level behavior deviation specification만으로는 직접 표현되지 않는다.

## Design Implication for This Project

현재 Maude DSL은 TLS message content를 대상으로 한 deviation에는 강하다. 특히 field replacement, extension/list add/remove, message omission, RFC check removal, object-state override를 표현할 수 있다. 또한 HRR, resumption, PSK, renegotiation, key-update처럼 여러 step이 필요한 path-level case도 모델에 해당 path가 있으면 여러 `BehaviorDVSpec`과 `scenarioProperty` 조합으로 표현할 수 있다. 따라서 논문에서는 C1-C4를 expressible class로 묶는 것이 자연스럽다.

반대로 C5-C6은 별도 확장이 필요하다. 필요한 확장은 크게 세 가지다.

- Record-byte layer: fragmentation/coalescence, ciphertext/tag/MAC/padding byte mutation, exact record boundary.
- Transport/timing control: TCP reset/FIN, missing `close_notify`, timeout, partial application data delivery, timing measurement.
- Observation/oracle model: alert/TCP/timeout/timing/differential response classification.
