# Expressibility Against the Current Maude DSL

이 문서는 [README.md](README.md)의 C1-C6 category가 현재 Maude behavior deviation specification과 `scenarioProperty` framework에서 어떻게 표현되는지 판정한 근거를 정리한다.

## Current DSL Surface

Behavior deviation specification은 `{Qid, ActionProposition, Set{BehaviorModification}}` 형태다. 현재 syntax는 다음 modification을 제공한다.

| Operation | Source Evidence | Meaning for Deviation |
|---|---|---|
| `setM(MessageId, MessageValue)` | `maude/scenario/behavior-specification-syntax.maude:132`; semantics `:482-562` | 기존 message field나 extension 값을 교체한다. C1의 핵심 연산이다. |
| `add(MessageId, MessageValue)` | `maude/scenario/behavior-specification-syntax.maude:133`; semantics `:563-632` | list, extension, singleton field를 추가한다. C2 일부를 표현한다. |
| `remove(MessageId)` | `maude/scenario/behavior-specification-syntax.maude:134`; semantics `:634-702` | field나 extension 전체를 제거한다. C2와 일부 C3 auth omission을 표현한다. |
| `noCheck(RFCLabel)` | `maude/scenario/behavior-specification-syntax.maude:135`; semantics `:315-317`, `:338-351` | 선택한 RFC requirement check를 제거한다. 메시지 자체보다는 rule guard deviation이다. |
| `skip()` | `maude/scenario/behavior-specification-syntax.maude:136`; semantics `:461-480`; `skipF` at `maude/mbt/formal-action.maude:77` | 선택된 action의 queued TLS message와 built transcript suffix를 제거한다. C3 omission 표현에 사용 가능하다. |
| `delay(HandshakeType)` | `maude/scenario/behavior-specification-syntax.maude:137` | Syntax는 있으나 현재 semantics의 effective case가 없다. 직접 reorder primitive로 보기 어렵다. |
| `setF(AttributeId, AttributeValue)` | `maude/scenario/behavior-specification-syntax.maude:131`; semantics `:711-795` | TLS/client/server object state를 바꾼다. C4의 selected cipher/state/path 조작에 사용할 수 있다. |

Deviation rule은 선택한 target TLS build/process rule에 guard와 modification을 적용한다. Target rules는 TLS 1.2와 TLS 1.3 build/process rules로 나뉘며, `deviateRule`은 `applyRules`, `addGuard`, `setLabels`를 통해 modified rules를 만든다 (`maude/scenario/behavior-specification-semantics.maude:23-88`, `:824-829`).

여러 `BehaviorDVSpec`은 하나의 `Set{BehaviorDVSpec}`로 함께 적용할 수 있고, `scenarioProperty`는 해당 deviation들이 적용된 실행에서 특정 rule sequence, feature map, object state, error state가 관측되는지를 지정한다. 따라서 C4처럼 여러 step의 path/state 조합이 필요한 경우도 현재 모델에 해당 build/process rule과 state가 존재하면 별도 implementation harness 없이 scenario 안에서 표현된다.

## Message Field Coverage

현재 `setM`은 다음 계열을 직접 다룬다.

- Record header: `#contentType`, `#version`, `#recordLen` (`maude/scenario/behavior-specification-semantics.maude:359-368`, `:482-484`).
- Alert: `#alertDesc`, `#alertLev` (`:485-486`).
- Handshake core: `#handshakeType`, `#handshakeLen`, `#protocol`, `#cipherSuites`, `#cipherSuitesLen`, `#random`, `#sessionId`, `#sessionIdLen`, compression fields (`:487-496`).
- Certificate/authentication: certificate list, certificate request fields, verify data, signature length, certificate-verify algorithm (`:497-520`).
- TLS 1.3 extensions: supported versions, signature algorithms, key shares, supported groups, PSK mode, selected identifier, PSK binders, early data, post-handshake, renegotiation info (`:524-560`).

따라서 C1 field/value modification은 현재 DSL에서 가장 명확히 표현된다.

## Category-by-Category Judgment

| Category | Expressible | Reason |
|---|---:|---|
| C1. Message Field/Value Modification | O | `setM`이 record header, alert, handshake, extension, certificate/auth fields를 다룬다. |
| C2. Message Structure/Component Modification | O | `add`와 `remove`가 modeled field/extension/list component 추가와 제거를 지원하고, `setM`으로 modeled component/list를 empty value로 교체할 수 있다. 이 판정은 behavior DSL에 존재하는 message component, extension, list 구조 조작에 한정한다. |
| C3. Protocol Message Flow/Ordering Modification | O/△ | `skip()`은 omission을 표현한다. Duplicate or inserted whole message는 scenario trace 구성으로 표현할 수 있지만, `BehaviorModification` 자체에는 whole-message insertion/reorder operator가 없다. `delay`는 syntax만 있고 effective semantics가 확인되지 않는다. |
| C4. Negotiation/Path/State Feature Modification | O | 현재 modeled negotiation/path/state deviation은 `setM` field/extension mutation, `setF` object-state mutation, `noCheck` guard relaxation으로 표현할 수 있다. 필요한 경우 여러 `BehaviorDVSpec`으로 관련 build/process rule을 함께 target하고 `scenarioProperty`로 expected outcome을 지정한다. 현재 모델에 없는 protocol path나 real implementation oracle concern은 expressibility 판정 범위 밖이다. |
| C5. Concrete Byte/Cryptographic Payload Modification | X | concrete byte mutation과 cryptographic payload/oracle change는 behavior deviation DSL 바깥이다. 예를 들어 record fragmentation/coalescence, byte truncation, ciphertext/tag/MAC byte flip, CBC padding/timing, RSA PKCS#1 premaster-secret ciphertext oracle는 현재 message-level model로 표현되지 않는다. record header field mutation은 C1의 `setM` 범주이며 C5 partial support로 세지 않는다. |
| C6. Transport/Timing Modification | X | TCP reset/FIN, missing close_notify, timeout, timing side channel, transport/application truncation, alert/TCP/timeout response classification 같은 transport/timing concern은 behavior deviation DSL에 표현 대상이 없다. certificate-list replacement/removal은 C2의 message component 조작으로 분류하며, X.509 certificate-internal mutation은 현재 table 범위에서 제외한다. |

## Important Limitations

Message content와 extension은 associative-commutative multiset 형태다. `maude/message.maude:5`는 `MsgContent` 조합 연산을 `assoc comm`으로 선언하고, `maude/tls-data.maude:303`도 `Extension` 조합을 `assoc comm`으로 선언한다. 따라서 modeled field/extension/list presence와 replacement는 표현할 수 있지만, message 내부 byte order, extension order, concrete byte shape는 모델의 핵심 구분자가 아니다. concrete byte-level mutation은 C5에 속한다. X.509 certificate-internal mutation은 현재 table의 category 범위에서 제외한다.

`add`는 많은 경우 기존 list나 `extensions(EXT)` wrapper가 있어야 효과가 있다. 존재하지 않는 형태에 대해 modification이 맞지 않으면 `applyMsg(MC, BMOD) = MC [owise]`로 no-op이 된다 (`maude/scenario/behavior-specification-semantics.maude:705`).

일부 syntax-level `MessageId`는 effective `applyMsg` case가 없거나 제한적이다. 예를 들어 `#serverkeyExchange`, `#clientPMSParam`, `#clientDHParam`, `#clientECDHParam`, `#newSessionTicket`는 syntax에 있으나 현재 semantics에서 직접 rewrite되지 않는 것으로 보인다. 또한 `#signature`의 `setM`은 전달된 nonce 값을 그대로 쓰지 않고 고정 형태로 바꾸는 특수 case가 있다 (`maude/scenario/behavior-specification-semantics.maude:510-511`).

`skip()`은 "이 rule/action이 만든 TLS message를 queue/transcript에서 제거"하는 연산이다. 임의의 network drop, TCP close, fatal/graceful termination, timeout을 모델링하는 일반 transport primitive는 아니다.

`maude/mbt/formal-action.maude`에는 low-level attacker-style action으로 `changeProtocolVersion`, `changeRecordType`, `changeRecordLen`, `changeHandshakeLen`, `closedConnectionF` 등이 존재한다 (`:123`, `:130`, `:137`, `:138`, `:150`). 그러나 이들은 현재 behavior deviation DSL의 `BehaviorModification` 범주와 동일하지 않다. 따라서 paper table의 expressibility는 behavior specification 기준으로 판정해야 한다.

## Extension Candidates

논문에서 C5-C6까지 coverage를 주장하려면 다음 확장이 필요하다.

| Needed Extension | What It Would Express |
|---|---|
| Record fragmentation/coalescence model | TLS-Anvil/FLEXTLS의 record fragment length, TCP fragmentation, one-byte alert fragmentation. |
| Concrete byte/cryptographic payload mutation | Byte truncation, Lucky Thirteen, padding-oracle scan, manipulated AEAD tag/ciphertext/MAC, malformed CBC padding. |
| RSA/crypto byte constructors | ROBOT, Bleichenbacher/Manger oracle, malformed PKCS#1 premaster-secret ciphertext. |
| Transport/timing model | TCP reset/FIN, missing `close_notify`, truncation, timeout, timing measurement, response map. |
| Observation/oracle semantics | Alert/TCP/timeout/timing/differential response classification across implementations. |
