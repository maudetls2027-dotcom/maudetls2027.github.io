# 논문용 TLS 구현 버그 분석 요약

이 문서는 `2026-01-01T00:00:00Z` 이후 `created_at` 기준으로 다시 수집한 결과를 기준으로 한다. 이전 작업 중 사용되던 `2326/231` 숫자는 stale working number이고, 재수집 결과는 `2421/212`이다.

## 1. 자동 수집 후보: 2,421건

다음을 기준으로 `tls_bug_analysis_pipeline.py`를 이용하여 자동 수집했다.

- 기준1. 대상 저장소는 `wolfSSL/wolfssl`, `Mbed-TLS/mbedtls`, `openssl/openssl`, `gnutls/gnutls` GitHub 저장소와 `gnutls/gnutls` GitLab 저장소이다.
- 기준2. `created_at >= 2026-01-01T00:00:00Z`인 issue, PR, MR을 대상으로 했다.
- 기준3. label에 `bug`, `defect`, `regression`, `type:bug`, `kind:bug` 등 bug signal이 있으면 `direct-bug-label`로 수집했다.
- 기준4. label이 없더라도 title/body에 `fix`, `regression`, `incorrect`, `invalid`, `failure`, `handshake`, `alert`, `certificate`, `cipher`, `record`, `tls`, `psk`, `finished`, `key share`, `ClientHello`, `ServerHello`, `compliance` 등 bug-like signal이 있으면 `bug-inferred`로 수집했다.
- 기준5. `CVE`, `GHSA`, `security`, `vulnerability`, `advisory` signal이 있으면 `security/advisory`로 분리했다.
- 기준6. `duplicate`는 별도 bug 수로 세지 않고 제외 signal로 표시했다.
- 기준7. `not a bug`, `expected behavior`, `works as intended`, `invalid`, `user error`, `configuration issue`, `wontfix` 등 maintainer가 bug가 아니라고 볼 가능성이 큰 signal은 제외 signal로 표시했다.

주의: 이 2,421건은 confirmed bug가 아니라 `bug-like candidate`이다.

## 2. 자동 RFC-probable 후보: 212건

다음을 기준으로 script를 이용하여 2,421건 중에서 자동으로 수집했다.

- 기준1. `RFC 5246`, `RFC 8446`, `TLS 1.2`, `TLS 1.3`, `ClientHello`, `ServerHello`, `Finished`, `CertificateVerify`, `PSK`, `binder`, `key_share`, `supported_versions`, `HelloRetryRequest`, `KeyUpdate`, `early data`, `record layer`, `alert`, `CertificateRequest`, `NewSessionTicket`, `renegotiation` 등 RFC/TLS core keyword가 있어야 한다.
- 기준2. 동시에 `MUST`, `MUST NOT`, `SHALL`, `violate`, `invalid`, `accept`, `reject`, `verify`, `validate`, `check`, `alert`, `unexpected_message`, `illegal_parameter`, `decode_error`, `missing_extension`, `conformance`, `compliance` 등 normative/failure keyword가 있어야 한다.
- 기준3. duplicate signal과 explicit not-a-bug signal이 있는 항목은 자동 RFC-probable 후보에서 제외했다.
- 기준4. 이 단계는 label/body/title metadata 기반 자동 후보 생성이며, maintainer 판단과 linked fix의 최종 source audit은 별도 단계로 둔다.

주의: 여기서 `자동 RFC-probable`은 heuristic filter 이름이다. 아래 수동/subagent triage의 `RFC-probable` class와 같은 의미가 아니다.

## 3. 212건 수동/subagent 분석 결과

212건에 대해서는 라이브러리별 chunk를 만들어 보수적으로 subagent metadata triage를 수행했다. 이 단계는 source-audited ground truth가 아니라, 논문용 source audit 전에 후보를 정리하는 단계이다.

- RFC-Core: 52건
- RFC-probable: 35건
- TLS-Adjacent: 98건
- Not-related: 27건

여기서 `RFC-Core + RFC-probable = 87건`이다. 이 87건은 TLS core 동작과 RFC conformance 위반 가능성이 있는 후보군이며, 아직 모두 confirmed RFC violation이라고 주장하면 안 된다.

## 4. RFC 5246/8446 해당 여부

87건 중 RFC 5246/8446 관련성을 다시 분리하면 다음과 같다.

- RFC 8446 only: 54건
- RFC 5246 only: 6건
- RFC 5246 + RFC 8446: 6건
- RFC 5246 + other RFC/protocol area: 4건
- RFC 8446 + other RFC/protocol area: 2건
- other RFC/protocol area only: 15건

논문에서 엄격히 `RFC 5246/8446만` 대상으로 삼으면 `54 + 6 + 6 = 66건`이다. `RFC 5246/8446과 다른 RFC/프로토콜 영역이 섞인 항목`까지 포함하면 `72건`이다. `other RFC/protocol area only` 15건은 TLS 관련성이 있더라도 RFC 5246/8446 본문 위반으로 주장하기 어렵다.

## 5. Root Cause 분류

RFC-Core/RFC-probable 87건을 primary root cause 기준으로 분류하면 다음과 같다.

- missing_validation: 24건
- wrong_error_handling: 15건
- wrong_validation_predicate: 13건
- incorrect_field_construction: 8건
- missing_state_transition_guard: 8건
- wrong_state_transition: 6건
- negotiation_logic_error: 5건
- incorrect_key_schedule: 4건
- incorrect_transcript_binding: 2건
- legacy_cross_version_error: 2건

각 카테고리 기준은 다음과 같다.

- missing_validation: RFC가 요구하는 검증 자체가 빠진 경우.
- wrong_validation_predicate: 검증은 있지만 concrete value의 비교 대상, boundary, equality/range/modulo 조건이 잘못된 경우.
- wrong_state_transition: handshake/message state가 RFC 순서와 다르게 이동하는 경우.
- missing_state_transition_guard: 특정 상태에서 메시지를 거부해야 하는 guard가 빠진 경우.
- incorrect_field_construction: wire message field, extension, length, version, group, cipher suite 구성이 잘못된 경우.
- incorrect_transcript_binding: Finished, CertificateVerify, PSK binder 등 transcript-bound 값의 입력/검증이 잘못된 경우.
- incorrect_key_schedule: TLS 1.3 key schedule, traffic secret, HKDF/derivation 동작이 잘못된 경우.
- negotiation_logic_error: version, cipher suite, group, extension selection logic이 잘못된 경우.
- wrong_error_handling: RFC가 요구하는 alert field 또는 검증 실패 이후 endpoint 진행 상태와 다른 경우. Alert level/description만 다른 경우는 wire-message construction으로, abort/continue/close처럼 진행 상태가 다른 경우는 state-machine progression으로 재배치한다.
- legacy_cross_version_error: TLS 1.2/1.3 또는 legacy compatibility field 경계에서 발생한 경우. 현재 item-level evidence가 Table III에 넣을 만큼 안정적이지 않으므로 논문용 expressibility table에서는 제외한다.

## 6. Behavior Deviation Specification 표현 가능성

현재 behavior deviation specification의 핵심 operation은 다음과 같다.

- `noCheck`: `rfc-requirement(label)` 조건을 제거하여 RFC 검증 누락을 표현한다.
- `setM/add/remove`: 모델에 존재하는 record/handshake message field 또는 extension을 변경, 추가, 제거한다.
- `setF`: TLS object state field, selected version/cipher/group, negotiated extension, state boolean 등을 변경한다.
- `skip()`: 해당 action의 message를 비우고, 이미 build된 transcript entry를 제거하는 방식으로 메시지 생략/전송 누락을 표현한다.

operation별 한계는 다음과 같다.

- `noCheck`는 모델링되지 않은 임의의 내부 validation condition을 제거하지 않는다. 현재 semantics에서는 `rfc-requirement(...) = true` 꼴로 모델링된 조건만 제거한다.
- `setM/add/remove`는 모델에 정의된 `MessageId`/`MessageValue` shape에 대해서만 동작한다. 지원되지 않는 field나 shape mismatch는 표현되지 않는다.
- `setF`는 이미 모델에 존재하는 object attribute만 바꾼다. 예를 들어 `clientState`/`serverState` 값을 직접 바꾸는 것은 가능하지만, 새로운 state-machine control-flow rule을 추가하는 것은 아니다.
- alert description/level은 `setM(#alertDesc, ...)`, `setM(#alertLev, ...)`로 조작 가능하다. 다만 abort/continue/close처럼 검증 실패 이후 endpoint가 어떤 세부 상태로 진행했는지는 현재 object attribute가 충분히 세분화되어 있을 때만 `setF`로 직접 표현된다.
- `setF(@sharedSecret, ...)`는 가능하지만, HKDF 단계나 traffic secret derivation 자체를 정확히 mutation하는 key schedule operation은 없다.

87건에 대한 표현 가능성 count를 요청한 scheme에 맞추면 다음과 같다.

- expressible_noCheck: 9건
- expressible_setF: 0건
- expressible_setM_add_remove: 17건
- expressible_skip: 0건
- expressible_combination: 6건
- partially_expressible: 33건
- not_expressible_current_model: 22건

여기서 `not_expressible_current_model`은 영구적으로 불가능하다는 의미가 아니라, 현재 operation set만으로는 정확히 표현되지 않고 semantic extension이 필요하다는 의미이다. 이 operation-level expressibility count는 아래 논문용 6-category O/X rebucketing과 분류 단위가 다르다. 아래 표에서는 alert field construction과 endpoint observable state progression을 각각 wire-message/state-machine category로 재배치한다.

현재 모델로 표현 가능한 카테고리는 다음과 같다.

- missing_validation: 대응되는 `rfc-requirement(label)`이 모델에 있으면 `noCheck`로 표현 가능하다.
- missing_state_transition_guard: guard가 `rfc-requirement(label)`로 모델링되어 있으면 `noCheck`로 표현 가능하다.
- incorrect_field_construction: 해당 field/extension이 모델에 있으면 `setM/add/remove`로 표현 가능하다.
- alert-message construction subset of wrong_error_handling: alert level/description은 모델에 `#alertLev`, `#alertDesc`로 존재하므로 `setM/add/remove`로 표현 가능하다.
- negotiation_logic_error: selected state를 `setF`로 바꾸고 peer message를 `setM/add/remove` 또는 `noCheck`와 결합하면 상당 부분 표현 가능하다. 단, modification set은 순서 의존 조합을 안정적으로 표현하는 용도가 아니다.
- endpoint-state subset of wrong_error_handling: 검증 실패 이후의 observable state가 모델 attribute로 드러나는 경우 `setF`로 표현 가능하다. abort/continue/close를 더 구체적으로 나누려면 endpoint attribute refinement가 필요하다.
- message omission / skipped send: 이번 87건의 primary expressibility count에는 별도 `expressible_skip`으로 잡힌 항목은 없지만, 모델 operation 자체로는 `skip()`을 통해 표현 가능하다.

operation을 추가하면 더 정확히 표현 가능한 카테고리는 다음과 같다.

- wrong_validation_predicate: 일반적인 predicate 전체가 아니라, 현재 symbolic `MessageValue` domain 밖의 concrete byte/numeric value, exact boundary, modulo, exact-consumption 조건을 직접 지정하는 operation 또는 value-domain refinement가 필요하다.
- wrong_state_transition: 단순히 잘못된 state value를 넣는 것은 `setF(@clientState, ...)` 또는 `setF(@serverState, ...)`로 가능하다. 다만 abort/continue/close 같은 post-failure distinction을 논문 artifact에서 더 정확히 보이려면 endpoint attribute를 더 세분화하는 refinement가 필요하다.
- wrong_error_handling: alert description/level만 다른 경우는 `setM(#alertDesc, ...)`, `setM(#alertLev, ...)`로 wire-message construction error에 포함한다. 검증 실패 후 silently accept, abort, continue, close처럼 endpoint 진행 상태가 다른 경우는 state-machine progression error로 본다.
- incorrect_transcript_binding: transcript input, hash coverage, binder/Finished/CV input을 조작하는 transcript-level operation이 필요하다.
- legacy_cross_version_error: TLS 1.2/1.3 compatibility field와 downgrade/legacy behavior를 cross-version rule로 다루는 operation이 필요하다.

현재 모델로 직접 표현하기 어려운 카테고리는 다음과 같다.

- incorrect_key_schedule: HKDF, traffic secret, key derivation, epoch별 secret update를 직접 조작하는 key-schedule semantics가 필요하다.
- RFC 5246/8446 밖의 Otherwise-only 항목: X.509, OCSP, PKCS, QUIC, DTLS-only, build/test/fuzz-only, provider/backend issue는 현재 TLS handshake behavior deviation model의 범위 밖이다.

## 7. 논문용 6-category 표

10개 root cause 중 `legacy_cross_version_error` 2건은 item-level evidence가 아직 안정적이지 않으므로 Table III에서는 제외한다. 아래 count는 나머지 `85건`을 6개 behavioral category로 압축한 것이다.

| Category | Included root causes | Count | Expressible (O/X) | Example |
|---|---:|---:|---:|---|
| Missing RFC checks and state guards | missing_validation 24 + missing_state_transition_guard 8 | 32 | O | `noCheck(label)`로 모델에 있는 RFC requirement/guard를 제거하여 invalid extension, missing mandatory value, unexpected message acceptance를 표현 |
| Wire-message construction errors | incorrect_field_construction 8 + alert-message construction subset of wrong_error_handling 9 | 17 | O | `setM(#supported-versions, ...)`, `add(#key-shares, ...)`, `remove(#pre-shared-key)`, `setM(#alertDesc, ...)`, `setM(#alertLev, ...)`로 wire field/extension/alert 구성 오류를 표현 |
| Negotiation and selected-parameter errors | negotiation_logic_error 5 | 5 | O | `setF(@selectedVersion, ...)`, `setF(@selectedCipherSuite, ...)`, `setF(@keyExchangeGroup, ...)`와 `setM/noCheck` 조합으로 잘못된 version/cipher/group 선택을 표현 |
| State-machine progression errors | wrong_state_transition 6 + endpoint-state subset of wrong_error_handling 6 | 12 | O | `setF(@clientState, ...)`, `setF(@serverState, ...)`, `skip()` 조합으로 endpoint가 잘못된 observable state에 도달하는 행동을 표현 |
| Concrete-value validation | wrong_validation_predicate 13 | 13 | X | concrete byte/numeric value, exact boundary, modulo, exact-consumption 조건처럼 현재 symbolic message-value domain 밖의 검증 조건은 직접 표현되지 않음 |
| Cryptographic binding | incorrect_key_schedule 4 + incorrect_transcript_binding 2 | 6 | X | HKDF/traffic secret, transcript input, Finished/CertificateVerify/PSK binder input은 별도 semantics 필요 |

위 표를 기준으로 하면 6개 category 중 4개 category, 총 66건은 현재 Behavior Deviation Specification으로 관찰 가능한 TLS behavior를 표현할 수 있다. 나머지 2개 category, 총 19건은 현재 operation set만으로는 정확히 표현하기 어렵고, concrete-value validation domain 또는 cryptographic-binding semantics extension이 필요하다.

주의: `Expressible = O`는 source-level root cause를 그대로 재현한다는 의미가 아니다. 논문에서는 “attacker-observable TLS behavior deviation을 현재 DSL로 표현 가능하다”라고 정의하는 것이 안전하다. 특히 state-machine progression의 `O`는 observable endpoint state/message behavior가 표현 가능하다는 뜻이며, 구현 내부의 새 transition rule을 faithful하게 추가한다는 뜻은 아니다.

### 7.1 Category description

- Missing RFC checks and state guards: RFC가 요구하는 validation 또는 state/message guard가 구현에서 빠져 invalid message를 수락하거나 잘못된 상태 진행을 허용하는 경우이다. 대응되는 requirement가 모델에 `rfc-requirement(label)`로 존재하면 `noCheck(label)`로 표현한다.
- Wire-message construction errors: ClientHello, ServerHello, extension, length, version, cipher suite, key share, alert level/description 등 wire message field를 잘못 만들거나 누락/추가하는 경우이다. 모델에 있는 field라면 `setM`, `add`, `remove`로 표현한다.
- Negotiation and selected-parameter errors: protocol version, cipher suite, group, selected extension처럼 협상 결과가 RFC 요구와 다르게 선택되는 경우이다. selected state는 `setF`로 바꾸고, 필요하면 peer message mutation이나 `noCheck`를 조합한다.
- State-machine progression errors: endpoint가 RFC handshake 순서와 다른 observable state에 도달하거나, 검증 실패 이후 silently accept, abort, continue, close처럼 다른 endpoint 진행 상태를 보이는 경우이다. 현재 모델에서는 `setF(@clientState, ...)`, `setF(@serverState, ...)`, `skip()`으로 관찰 가능한 state deviation을 표현할 수 있다. abort/continue/close를 더 세밀하게 구분하려면 endpoint attribute를 refinement하면 된다.
- Concrete-value validation: 검증이 빠진 것이 아니라 concrete byte/numeric value에 의존하는 boundary, equality, range, modulo, exact-consumption 조건이 RFC와 다른 경우이다. 현재 DSL은 `mv[valid]`, `mv[smaller]`, `mv[larger]`, `mv[minSize]`, `mv[maxSize]` 같은 symbolic value bucket을 중심으로 동작하므로, 임의의 concrete value 조건을 first-class로 지정하려면 value-domain refinement가 필요하다.
- Cryptographic binding: transcript coverage, Finished/CertificateVerify/PSK binder input, HKDF/traffic secret derivation 자체가 틀린 경우이다. 현재 DSL에는 transcript-level/key-schedule-level mutation이 없으므로 semantic extension이 필요하다.

### 7.2 Count verification 방법

자동 수집 후보 2,421건은 다음 명령으로 확인할 수 있다.

```sh
python3 - <<'PY'
import json
print(len(json.load(open('docs/tls-implementation-analysis/auto_candidates.json'))))
PY
```

자동 RFC-probable 후보 212건은 다음 명령으로 확인할 수 있다.

```sh
python3 - <<'PY'
import json
print(len(json.load(open('docs/tls-implementation-analysis/auto_rfc_probable_candidates.json'))))
PY
```

212건이 라이브러리별 review chunk로 모두 나뉘었는지는 다음 명령으로 확인할 수 있다.

```sh
python3 - <<'PY'
import json
from pathlib import Path
total = 0
for p in sorted(Path('docs/tls-implementation-analysis/review_chunks').glob('*.json')):
    n = len(json.load(open(p)))
    total += n
    print(f'{p.name}: {n}')
print('total:', total)
PY
```

논문용 보수적 집계, 즉 `RFC-Core 52`, `RFC-probable 35`, `TLS-Adjacent 98`, `Not-related 27`은 다음 명령으로 확인할 수 있다.

```sh
python3 - <<'PY'
import json
d = json.load(open('docs/tls-implementation-analysis/subagent_triage_counts.json'))
print(d['manual_subagent_classification_counts'])
print('total:', sum(d['manual_subagent_classification_counts'].values()))
print('RFC-Core + RFC-probable:', d['rfc_core_or_probable_total'])
PY
```

root cause 10개 category의 합계가 87인지 확인하려면 다음 명령을 사용한다.

```sh
python3 - <<'PY'
import json
d = json.load(open('docs/tls-implementation-analysis/subagent_triage_counts.json'))
for k, v in d['root_cause_counts_rfc_core_or_probable'].items():
    print(f'{k}: {v}')
print('total:', sum(d['root_cause_counts_rfc_core_or_probable'].values()))
PY
```

논문용 6-category table의 count가 85이고, O/X count가 각각 맞는지는 다음 명령으로 확인한다. `wrong_error_handling` 15건은 더 이상 독립 category로 두지 않고, alert-message construction subset 9건과 endpoint-state subset 6건으로 재배치한다. `legacy_cross_version_error` 2건은 Table III에서 제외한다.

```sh
python3 - <<'PY'
import json
d = json.load(open('docs/tls-implementation-analysis/subagent_triage_counts.json'))
rc = d['root_cause_counts_rfc_core_or_probable']
alert_message_construction = 9
endpoint_state_error_handling = rc['wrong_error_handling'] - alert_message_construction
cats = {
    'missing_rfc_checks_and_state_guards': (rc['missing_validation'] + rc['missing_state_transition_guard'], 'O'),
    'wire_message_construction_errors': (rc['incorrect_field_construction'] + alert_message_construction, 'O'),
    'negotiation_and_selected_parameter_errors': (rc['negotiation_logic_error'], 'O'),
    'state_machine_progression_errors': (rc['wrong_state_transition'] + endpoint_state_error_handling, 'O'),
    'concrete_value_validation': (rc['wrong_validation_predicate'], 'X'),
    'cryptographic_binding': (
        rc['incorrect_key_schedule'] + rc['incorrect_transcript_binding'], 'X'),
}
for k, (count, expr) in cats.items():
    print(f'{k}: {count}, expressible={expr}')
print('total:', sum(count for count, _ in cats.values()))
print('O:', sum(count for count, expr in cats.values() if expr == 'O'))
print('X:', sum(count for count, expr in cats.values() if expr == 'X'))
PY
```

작성 시 날짜도 조심해야 한다. 현재 재수집 corpus는 `created_at >= 2026-01-01T00:00:00Z` 기준이다. 논문에 “2016년부터”라고 쓰려면 같은 pipeline을 2016 cutoff로 다시 수집해야 한다.

## 8. 논문에 사용할 결론 형태

논문 본문에서는 다음처럼 쓰는 것이 가장 안전하다.

- 자동 수집으로 2,421건의 bug-like 후보를 얻었다.
- RFC/TLS core keyword와 normative/failure keyword를 이용해 212건의 RFC-probable 후보로 좁혔다.
- 212건을 보수적으로 수동/subagent triage한 결과, RFC-Core 52건과 RFC-probable 35건을 얻었다.
- 이 중 엄격히 RFC 5246/8446에만 속하는 후보는 66건이고, RFC 5246/8446과 다른 영역이 섞인 후보까지 포함하면 72건이다.
- 현재 behavior deviation specification은 validation omission, modeled message field construction, 일부 negotiation logic bug를 직접 표현할 수 있다.
- concrete-value validation과 cryptographic binding bug는 현재 일부만 표현되며, 정확한 재현에는 value-domain refinement나 semantic extension이 필요하다. Alert level/description 자체는 message field로 모델링되어 `setM`으로 표현 가능하고, abort/continue/close 같은 post-failure behavior는 endpoint attribute를 더 세분화하면 state mutation으로 다룰 수 있다.

## 9. 주의 사항

이 문서의 수동/subagent 결과는 metadata와 raw API evidence를 기반으로 한 보수적 triage이다. 논문 최종 숫자로 고정하려면 각 RFC-Core/RFC-probable 항목마다 maintainer comment, linked PR/MR, commit, release note, advisory를 확인해 `developer-recognized bug` 조건을 source-audit해야 한다.

## 10. Audit Sheet

아래 audit sheet는 논문용 6-category count인 85건과 Table III에서 제외한 legacy cross-version 후보를 item-by-item으로 확인하기 위한 source-audit 대상 목록이다. 이 목록은 `manual_triage_auto_rfc_probable.json`의 212개 자동 RFC-probable 후보에서 category quota에 맞춰 구성한 draft이므로, 각 row의 최종 포함 여부는 maintainer comment, linked PR/MR, commit, release note, advisory를 확인한 뒤 `audit_decision`으로 확정해야 한다.

주의: 이 표는 최종 evidence table이 아니라 review queue이다. 보수적 subagent triage의 item-level mapping이 별도 파일로 저장되어 있지 않기 때문에, 일부 row는 `Current class`가 `TLS-Adjacent` 또는 `Not-related`로 남아 있을 수 있다. 그런 row는 source-audit에서 `include`, `replace`, `exclude` 중 하나로 확정해야 한다.

실제 편집용 파일도 함께 생성했다: `docs/tls-implementation-analysis/audit_sheet_87_draft.csv`, `docs/tls-implementation-analysis/audit_sheet_87_draft.json`. 단, 아래 Markdown table은 이번 category rebucketing을 반영한 것이고, CSV/JSON draft artifact를 최종 evidence table로 쓰려면 같은 rebucketing을 반영해 다시 생성해야 한다.

### 10.1 Audit Sheet Count Check

주의: 아래 `Expected aggregate`는 논문 본문용 root-cause aggregate count이다. `Rows in draft sheet`는 현재 review queue row를 새 category label로 재배치했을 때의 분포이다. 이 draft sheet는 source-audit 전 review queue라서 row-level root-cause 분포가 aggregate count와 완전히 일치하지 않는다.

| Category | Expected aggregate | Rows in draft sheet | Expressible |
|---|---:|---:|---:|
| Missing RFC checks and state guards | 32 | 32 | O |
| Wire-message construction errors | 17 | 17 | O |
| Negotiation and selected-parameter errors | 5 | 5 | O |
| State-machine progression errors | 12 | 18 | O |
| Concrete-value validation | 13 | 7 | X |
| Cryptographic binding | 6 | 7 | X |
| Excluded from Table III: legacy cross-version | 2 | 1 |  |
| Total | 85 | 87 |  |

검산 명령은 다음과 같다.

```sh
python3 - <<'PY'
import collections, json, re
from pathlib import Path

d = json.load(open('docs/tls-implementation-analysis/subagent_triage_counts.json'))
rc = d['root_cause_counts_rfc_core_or_probable']
alert_message_construction = 9
endpoint_state_error_handling = rc['wrong_error_handling'] - alert_message_construction
expected = {
    'Missing RFC checks and state guards': rc['missing_validation'] + rc['missing_state_transition_guard'],
    'Wire-message construction errors': rc['incorrect_field_construction'] + alert_message_construction,
    'Negotiation and selected-parameter errors': rc['negotiation_logic_error'],
    'State-machine progression errors': rc['wrong_state_transition'] + endpoint_state_error_handling,
    'Concrete-value validation': rc['wrong_validation_predicate'],
    'Cryptographic binding':
        rc['incorrect_key_schedule'] + rc['incorrect_transcript_binding'],
}
print('expected aggregate:', expected)
print('expected total:', sum(expected.values()))

text = Path('docs/tls-implementation-analysis/paper_summary.md').read_text()
draft_rows = []
for line in text.splitlines():
    if re.match(r'^\| AS-\d+ \|', line):
        cols = [c.strip() for c in line.strip('|').split('|')]
        draft_rows.append(cols)
print('draft rows:', len(draft_rows))
print('draft row categories:', collections.Counter(r[1] for r in draft_rows))
print('draft row expressible:', collections.Counter(r[2] for r in draft_rows))
PY
```

### 10.2 Per-Item Audit Sheet

| ID | Category | Expr | Library | Current class | Root cause | RFC | Title / evidence | Audit |
|---|---|---:|---|---|---|---|---|---|
| AS-001 | Missing RFC checks and state guards | O | wolfSSL | RFC-Core | missing_validation | RFC8446 | [TLS 1.3: gate 0-RTT on a cache-backed resumption ticket](https://github.com/wolfSSL/wolfssl/pull/10289) | TBD |
| AS-002 | Missing RFC checks and state guards | O | GnuTLS | RFC-Core | missing_state_transition_guard | RFC8446 | [malformed CCS in TLS 1.3 is discarded without an alert](https://gitlab.com/gnutls/gnutls/-/work_items/1788) | TBD |
| AS-003 | Missing RFC checks and state guards | O | GnuTLS | RFC-Core | missing_state_transition_guard | RFC8446 | [two KeyUpdates in one record do not get rejected with unexpected_message](https://gitlab.com/gnutls/gnutls/-/work_items/1789) | TBD |
| AS-004 | Missing RFC checks and state guards | O | OpenSSL | RFC-Core | missing_validation | RFC5246;RFC8446 | [TLS 1.3 client does not validate ticket_lifetime <= 604800 per RFC 8446…](https://github.com/openssl/openssl/issues/30808) | TBD |
| AS-005 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC8446 | [Fix SSL_SESSION leak in tls_parse_ctos_psk() on ticket error paths](https://github.com/openssl/openssl/pull/30464) | TBD |
| AS-006 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC8446 | [Design gap: multiple TLS 1.3 signature schemes sharing the same key typ…](https://github.com/openssl/openssl/issues/31330) | TBD |
| AS-007 | Missing RFC checks and state guards | O | Mbed TLS | RFC-probable | missing_validation | RFC8446 | [Fix missing type conversion in the TLS-Exporter](https://github.com/Mbed-TLS/mbedtls/pull/10601) | TBD |
| AS-008 | Missing RFC checks and state guards | O | Mbed TLS | RFC-probable | missing_validation | RFC8446 | [[Backport 3.6] Fix missing type conversion in the TLS-Exporter](https://github.com/Mbed-TLS/mbedtls/pull/10602) | TBD |
| AS-009 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC5246;RFC8446 | [DTLS 1.3 Update Epoch to a 64 bit counter and don't allow wrapping](https://github.com/openssl/openssl/pull/30394) | TBD |
| AS-010 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation | RFC8446 | [verify ciphersuite in CH2 matches HRR](https://github.com/wolfSSL/wolfssl/pull/10034) | TBD |
| AS-011 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation | RFC8446 | [DTLS 1.3 client-only minimum: WOLFSSL_DTLS_ONLY + autoconf cascade](https://github.com/wolfSSL/wolfssl/pull/10353) | TBD |
| AS-012 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation | RFC5246 | [Check SNI/ALPN in TLS 1.2/1.3 session resumptions](https://github.com/wolfSSL/wolfssl/pull/10489) | TBD |
| AS-013 | Missing RFC checks and state guards | O | OpenSSL | TLS-Adjacent | missing_validation | RFC5246;RFC8446 | [Inconsistent certificate verify error strings for validity](https://github.com/openssl/openssl/issues/30915) | TBD |
| AS-014 | Missing RFC checks and state guards | O | OpenSSL | TLS-Adjacent | missing_validation | RFC5246;RFC8446 | [dtls: buffer early CCS to handle UDP reorder](https://github.com/openssl/openssl/pull/30225) | TBD |
| AS-015 | Missing RFC checks and state guards | O | OpenSSL | Not-related | missing_validation | RFC5246;RFC8446 | [DTLS 1.3 Epoch bits that don't match are from a prior epoch](https://github.com/openssl/openssl/pull/30570) | TBD |
| AS-016 | Missing RFC checks and state guards | O | OpenSSL | RFC-Core | missing_validation | RFC8446 | [doc: clarify SSL_SESSION ownership in PSK use session callback](https://github.com/openssl/openssl/pull/29771) | TBD |
| AS-017 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC8446 | [Fix NULL pointer dereference when zlib DSO fails to load](https://github.com/openssl/openssl/pull/29699) | TBD |
| AS-018 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC5246;RFC8446 | [ssl: realloc pipe buffer when pipe count decreases](https://github.com/openssl/openssl/pull/30480) | TBD |
| AS-019 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC5246;RFC8446 | [ISSUE-30458: Fix leak when replacing stacked record-layer transport BIO](https://github.com/openssl/openssl/pull/30483) | TBD |
| AS-020 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation | RFC8446 | [Memory safety code review: 17 findings across compiled sources](https://github.com/wolfSSL/wolfssl/issues/10063) | TBD |
| AS-021 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC8446 | [Fix NULL pointer dereference when zlib DSO fails to load](https://github.com/openssl/openssl/pull/29698) | TBD |
| AS-022 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation | RFC8446 | [check that we are resuming in write_early_data + minor fixes](https://github.com/wolfSSL/wolfssl/pull/9601) | TBD |
| AS-023 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation |  | [Add check for KS in SH](https://github.com/wolfSSL/wolfssl/pull/9754) | TBD |
| AS-024 | Missing RFC checks and state guards | O | OpenSSL | Not-related | missing_validation | RFC5246;RFC8446 | [doc: clarify -CAfile and -verifyCAfile semantics in openssl-s_server .p…](https://github.com/openssl/openssl/pull/30405) | TBD |
| AS-025 | Missing RFC checks and state guards | O | wolfSSL | Not-related | missing_validation | RFC5246;RFC8446 | [fix: enforce pathlen constraint in X509 API verify path](https://github.com/wolfSSL/wolfssl/pull/10651) | TBD |
| AS-026 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation | RFC8446 | [CI Addition (ECH): Check only the public SNI is visible](https://github.com/wolfSSL/wolfssl/pull/10542) | TBD |
| AS-027 | Missing RFC checks and state guards | O | OpenSSL | RFC-probable | missing_validation | RFC8446 | [OpenSSL session resumption performance measurement](https://github.com/openssl/openssl/issues/30456) | TBD |
| AS-028 | Missing RFC checks and state guards | O | OpenSSL | Not-related | missing_validation | RFC5246;RFC8446 | [x509: reject unauthorized stapled OCSP response signers](https://github.com/openssl/openssl/pull/30323) | TBD |
| AS-029 | Missing RFC checks and state guards | O | OpenSSL | Not-related | missing_validation |  | [Add Ed25519 Cert. Support for DTLS 1.2](https://github.com/openssl/openssl/pull/30007) | TBD |
| AS-030 | Missing RFC checks and state guards | O | OpenSSL | Not-related | missing_validation | RFC8446 | [make TLS session resumption working for QUIC](https://github.com/openssl/openssl/pull/30750) | TBD |
| AS-031 | Missing RFC checks and state guards | O | OpenSSL | RFC-Core | missing_validation | RFC5246;RFC8446 | [ISSUE-28348: Deprecate SSL_COMP and related functions](https://github.com/openssl/openssl/pull/30439) | TBD |
| AS-032 | Missing RFC checks and state guards | O | wolfSSL | RFC-probable | missing_validation | RFC8446 | [Improve user_settings.h examples and add validation rules](https://github.com/wolfSSL/wolfssl/pull/9719) | TBD |
| AS-033 | Wire-message construction errors | O | wolfSSL | RFC-Core | incorrect_field_construction | RFC8446 | [[Bug]: 0-RTT Anti-Replay Minimum Requirement Not Enforced (RFC 8446 Sec…](https://github.com/wolfSSL/wolfssl/issues/10197) | TBD |
| AS-034 | Wire-message construction errors | O | wolfSSL | RFC-Core | incorrect_field_construction | RFC8446 | [[Bug]: `ticket_lifetime = 0` and Immediate Discard Semantics](https://github.com/wolfSSL/wolfssl/issues/10322) | TBD |
| AS-035 | Wire-message construction errors | O | wolfSSL | RFC-Core | incorrect_field_construction | RFC5246;RFC8446 | [[Bug]: client_certificate_type and server_certificate_type extensions a…](https://github.com/wolfSSL/wolfssl/issues/9655) | TBD |
| AS-036 | Wire-message construction errors | O | Mbed TLS | RFC-Core | incorrect_field_construction | RFC8446 | [mbedTLS TLS 1.3 `certificate_authorities` Validation Gap](https://github.com/Mbed-TLS/mbedtls/issues/10744) | TBD |
| AS-037 | Wire-message construction errors | O | OpenSSL | RFC-Core | incorrect_field_construction | RFC8446 | [Disable tickets when SSL_OP_NO_TICKET and SSL_SESS_CACHE_OFF are set](https://github.com/openssl/openssl/pull/30639) | TBD |
| AS-038 | Wire-message construction errors | O | wolfSSL | RFC-Core | incorrect_field_construction | RFC5246;RFC8446 | [Fix TLSX_Parse to correctly handle client and server cert type ext with…](https://github.com/wolfSSL/wolfssl/pull/9657) | TBD |
| AS-039 | Wire-message construction errors | O | wolfSSL | RFC-Core | incorrect_field_construction | RFC8446 | [reject extensions in a TLS 1.3 Certificate message that were not offere…](https://github.com/wolfSSL/wolfssl/pull/10338) | TBD |
| AS-040 | Wire-message construction errors | O | Mbed TLS | RFC-Core | incorrect_field_construction | RFC8446 | [TLS 1.3 KeyShare Ordering Semantics Are Only Partially Covered](https://github.com/Mbed-TLS/mbedtls/issues/10722) | TBD |
| AS-041 | Negotiation and selected-parameter errors | O | wolfSSL | RFC-Core | negotiation_logic_error | RFC5246;RFC8446 | [DTLS 1.3 Dynamic Connection ID Update Semantics Are Missing](https://github.com/wolfSSL/wolfssl/issues/10613) | TBD |
| AS-042 | Negotiation and selected-parameter errors | O | Mbed TLS | RFC-probable | negotiation_logic_error | RFC5246 | [Backport 4.1: ssl: accept TLS 1.2 rsa_pss_rsae signature algorithms](https://github.com/Mbed-TLS/mbedtls/pull/10704) | TBD |
| AS-043 | Negotiation and selected-parameter errors | O | Mbed TLS | RFC-probable | negotiation_logic_error | RFC8446 | [check_config: add missing check for TLS 1.3 key exchanges](https://github.com/Mbed-TLS/mbedtls/pull/10650) | TBD |
| AS-044 | Negotiation and selected-parameter errors | O | Mbed TLS | RFC-probable | negotiation_logic_error | RFC5246 | [Backport 3.6: ssl: accept TLS 1.2 rsa_pss_rsae signature algorithms](https://github.com/Mbed-TLS/mbedtls/pull/10674) | TBD |
| AS-045 | Negotiation and selected-parameter errors | O | Mbed TLS | RFC-probable | negotiation_logic_error | RFC8446 | [[backport 4.1] check_config: add missing check for TLS 1.3 key exchanges](https://github.com/Mbed-TLS/mbedtls/pull/10713) | TBD |
| AS-046 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_state_transition | RFC8446 | [[Bug]: wolfSSL certificate_authorities Length-Boundary Verification](https://github.com/wolfSSL/wolfssl/issues/10316) | TBD |
| AS-047 | State-machine progression errors | O | OpenSSL | RFC-Core | wrong_state_transition | RFC8446 | [Reject empty TLS 1.3 HRR cookie](https://github.com/openssl/openssl/pull/30892) | TBD |
| AS-048 | State-machine progression errors | O | OpenSSL | RFC-Core | wrong_state_transition | RFC8446 | [s_server -www sends NewSessionTicket instead of required KeyUpdate resp…](https://github.com/openssl/openssl/issues/31227) | TBD |
| AS-049 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_state_transition | RFC8446 | [[Bug]: DTLS 1.3 close_notify Does Not Preserve the Epoch/Sequence Bound…](https://github.com/wolfSSL/wolfssl/issues/10614) | TBD |
| AS-050 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_state_transition | RFC5246;RFC8446 | [DTLS 1.3 close_notify Lacks Epoch/Sequence Boundary Tracking](https://github.com/wolfSSL/wolfssl/issues/10623) | TBD |
| AS-051 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_state_transition | RFC5246;RFC8446 | [Fenrir 2026-06-02: TLS/DTLS correctness, resumption & renegotiation saf…](https://github.com/wolfSSL/wolfssl/pull/10582) | TBD |
| AS-052 | Wire-message construction errors | O | Mbed TLS | RFC-Core | wrong_error_handling | RFC8446 | [mbedTLS TLS 1.3 weak-hash certificate alert mapping inconsistency](https://github.com/Mbed-TLS/mbedtls/issues/10718) | TBD |
| AS-053 | Wire-message construction errors | O | OpenSSL | RFC-Core | wrong_error_handling | RFC8446 | [Explanation of the Alert Semantic Difference in the Certificate Signatu…](https://github.com/openssl/openssl/issues/30879) | TBD |
| AS-054 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_error_handling | RFC5246;RFC8446 | [[Bug]: RFC 5246 violation: empty server certificate not rejected in TLS…](https://github.com/wolfSSL/wolfssl/issues/9651) | TBD |
| AS-055 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_error_handling | RFC8446 | [[Bug]: HelloRetryRequest Extension Whitelist Runtime Recheck](https://github.com/wolfSSL/wolfssl/issues/10320) | TBD |
| AS-056 | State-machine progression errors | O | OpenSSL | RFC-Core | wrong_error_handling | RFC8446 | [TLS 1.3 server silently accepts ClientHello missing required key_share …](https://github.com/openssl/openssl/issues/31229) | TBD |
| AS-057 | Wire-message construction errors | O | wolfSSL | RFC-Core | wrong_error_handling | RFC8446 | [TLS 1.3 (RFC 8446) Incompliance Observations in wolfSSL](https://github.com/wolfSSL/wolfssl/issues/10244) | TBD |
| AS-058 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_error_handling | RFC8446 | [Treat alerts as fatal errors regardless of level in TLS1.3](https://github.com/wolfSSL/wolfssl/pull/9875) | TBD |
| AS-059 | Wire-message construction errors | O | wolfSSL | RFC-Core | wrong_error_handling | RFC8446 | [tls.c: send missing_extension alert on TLS 1.3 SNI absence](https://github.com/wolfSSL/wolfssl/pull/10332) | TBD |
| AS-060 | Concrete-value validation | X | Mbed TLS | RFC-Core | wrong_validation_predicate | RFC5246;RFC8446 | [mbedTLS TLS 1.3 X.509 `cert_data` length boundary inconsistency](https://github.com/Mbed-TLS/mbedtls/issues/10719) | TBD |
| AS-061 | Wire-message construction errors | O | Mbed TLS | RFC-Core | wrong_error_handling | RFC8446 | [Empty Client Certificate Uses `no_certificate` Instead of `certificate_…](https://github.com/Mbed-TLS/mbedtls/issues/10720) | TBD |
| AS-062 | Concrete-value validation | X | Mbed TLS | RFC-Core | wrong_validation_predicate | RFC8446 | [mbedTLS Does Not Strictly Enforce the `ServerHello.key_share` Exact Len…](https://github.com/Mbed-TLS/mbedtls/issues/10737) | TBD |
| AS-063 | State-machine progression errors | O | wolfSSL | RFC-probable | wrong_error_handling | RFC8446 | [[Bug]: DTLS 1.3 with PSK failing because of missing SignatureAlgorithms…](https://github.com/wolfSSL/wolfssl/issues/9876) | TBD |
| AS-064 | Wire-message construction errors | O | OpenSSL | RFC-probable | wrong_error_handling | RFC5246;RFC8446 | [Correct alert when extended master secret support is dropped](https://github.com/openssl/openssl/pull/29706) | TBD |
| AS-065 | State-machine progression errors | O | OpenSSL | RFC-probable | wrong_error_handling | RFC5246;RFC8446 | [Enabling the DTLS 1.3 Message tests](https://github.com/openssl/openssl/pull/29961) | TBD |
| AS-066 | Concrete-value validation | X | OpenSSL | RFC-probable | wrong_validation_predicate | RFC5246 | [TLS: Verify session ID to prevent incorrect session resumption](https://github.com/openssl/openssl/pull/30517) | TBD |
| AS-067 | Concrete-value validation | X | wolfSSL | RFC-probable | wrong_validation_predicate | RFC5246;RFC8446 | [[Bug]: CMake DTLS CID Option Incorrectly Requires DTLS 1.3](https://github.com/wolfSSL/wolfssl/issues/10610) | TBD |
| AS-068 | Concrete-value validation | X | wolfSSL | RFC-probable | wrong_validation_predicate | RFC8446 | [[Bug]: DTLS 1.3 legacy_session_id Handling Is Implemented, but Pre-DTLS…](https://github.com/wolfSSL/wolfssl/issues/10618) | TBD |
| AS-069 | State-machine progression errors | O | OpenSSL | RFC-probable | wrong_error_handling | RFC5246;RFC8446 | [Unable to pass empty list to -alpn in s_sclient](https://github.com/openssl/openssl/issues/31088) | TBD |
| AS-070 | Wire-message construction errors | O | wolfSSL | RFC-probable | wrong_error_handling | RFC5246;RFC8446 | [Send alert in case of decrypted all-zero message](https://github.com/wolfSSL/wolfssl/pull/9882) | TBD |
| AS-071 | Wire-message construction errors | O | wolfSSL | RFC-probable | wrong_error_handling | RFC5246;RFC8446 | [Fix alert type for missing cert. Prevent building with RNG disabled and…](https://github.com/wolfSSL/wolfssl/pull/10462) | TBD |
| AS-072 | State-machine progression errors | O | Mbed TLS | RFC-probable | wrong_error_handling | RFC8446 | [ssl: reject trailing bytes in TLS 1.3 encrypted extensions](https://github.com/Mbed-TLS/mbedtls/pull/10752) | TBD |
| AS-073 | Wire-message construction errors | O | OpenSSL | RFC-probable | wrong_error_handling | RFC8446 | [Fix TLS 1.3 missing key_share alert](https://github.com/openssl/openssl/pull/30851) | TBD |
| AS-074 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_error_handling | RFC8446 | [[Bug]: ServerHello Extension Whitelist Runtime Recheck](https://github.com/wolfSSL/wolfssl/issues/10321) | TBD |
| AS-075 | State-machine progression errors | O | wolfSSL | RFC-Core | wrong_error_handling | RFC8446 | [TLS ECH Compliance Fixes](https://github.com/wolfSSL/wolfssl/pull/10141) | TBD |
| AS-076 | State-machine progression errors | O | OpenSSL | RFC-probable | wrong_error_handling | RFC5246;RFC8446 | [Detecting plaintext HTTP over a TLS socket is broken for certain verbs](https://github.com/openssl/openssl/issues/30196) | TBD |
| AS-077 | Concrete-value validation | X | wolfSSL | RFC-probable | wrong_validation_predicate | RFC8446 | [[Bug]: Hardening fixes for src/tls13.c](https://github.com/wolfSSL/wolfssl/issues/10313) | TBD |
| AS-078 | State-machine progression errors | O | GnuTLS | RFC-probable | wrong_error_handling | RFC8446 | [tests/suite/tls-fuzzer: update submodules, tweak/enable tests](https://gitlab.com/gnutls/gnutls/-/merge_requests/2055) | TBD |
| AS-079 | Concrete-value validation | X | GnuTLS | RFC-probable | wrong_validation_predicate | RFC8446 | [Vulnerability in GnuTLS PSK/SRP rehandshake handling](https://gitlab.com/gnutls/gnutls/-/issues/1808) | TBD |
| AS-080 | Cryptographic binding | X | Mbed TLS | RFC-Core | incorrect_transcript_binding | RFC8446 | [Comprehensive Analysis: TLS 1.3 Certificate Signature Algorithm Constra…](https://github.com/Mbed-TLS/mbedtls/issues/10693) | TBD |
| AS-081 | Cryptographic binding | X | Mbed TLS | RFC-Core | incorrect_transcript_binding | RFC8446 | [TLS 1.3 Certificate Signature Algorithm Constraint](https://github.com/Mbed-TLS/mbedtls/issues/10732) | TBD |
| AS-082 | Cryptographic binding | X | wolfSSL | RFC-Core | incorrect_key_schedule | RFC8446 | [[Bug]: In case of DTLS 1.3 when using NULL cipher the Nonce length seem…](https://github.com/wolfSSL/wolfssl/issues/9757) | TBD |
| AS-083 | Cryptographic binding | X | Mbed TLS | RFC-Core | incorrect_transcript_binding | RFC8446 | [TLS 1.3: Enforce that handshake messages do not span key changes](https://github.com/Mbed-TLS/mbedtls/issues/10708) | TBD |
| AS-084 | Cryptographic binding | X | OpenSSL | RFC-Core | incorrect_key_schedule | RFC8446 | [Inconsistent TLS 1.3 key schedule secret cleanup in SSL_CONNECTION](https://github.com/openssl/openssl/issues/30849) | TBD |
| AS-085 | Excluded from Table III: legacy cross-version |  | wolfSSL | RFC-Core | legacy_cross_version_error | RFC5246;RFC8446 | [[TLS 1.2, TLS 1.3] Fail immediately if server sends empty certificate m…](https://github.com/wolfSSL/wolfssl/pull/9662) | TBD |
| AS-086 | Cryptographic binding | X | wolfSSL | RFC-Core | incorrect_transcript_binding | RFC8446 | [TLS 1.3: evict session from cache after accepted 0-RTT resumption](https://github.com/wolfSSL/wolfssl/pull/10221) | TBD |
| AS-087 | Cryptographic binding | X | wolfSSL | RFC-Core | incorrect_key_schedule | RFC5246;RFC8446 | [Zero TLS 1.3 traffic keys after AES SE offload](https://github.com/wolfSSL/wolfssl/pull/10246) | TBD |

Audit column의 `TBD`는 아직 source-audit이 끝나지 않았다는 뜻이다. 최종 논문 수치로 고정하려면 각 row마다 개발자/maintainer가 bug로 인정했는지, fixed 상태인지, duplicate인지, RFC 5246/8446 본문 위반으로 주장 가능한지를 확인해야 한다.
