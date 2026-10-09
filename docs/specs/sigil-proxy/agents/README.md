# Sigil Proxy 에이전트 운영 정의

2026-09-27 · 역할 정의 완료, 실행 인스턴스는 아직 시작하지 않음.

사용자는 이 대화의 **오케스트레이터**에게만 지시하고 통합 보고를 받는다.
역할 파일은 작업 배정 시 전달할 지침이며, 자동 등록된 상시 실행 agent 설정이 아니다.
새 세션에서도 루트 AGENTS.md와 이 문서를 읽고 같은 운영 방식을 이어간다.

## 역할

| 역할 ID | 정의 | 책임 |
|---|---|---|
| orchestrator | [오케스트레이터](orchestrator.md) | 사용자 창구, 범위·의존성·배정·통합·완료 판정 |
| researcher | [조사](researcher.md) | 공식 문서, 로컬 버전, 호환성·기존 구조 근거 |
| coder | [코딩](coder.md) | 확정 계약에 따른 구현과 관련 테스트 |
| reviewer | [코드 리뷰](reviewer.md) | 독립 검토, 보안·계약·회귀 결함 발견 |
| verifier | [검증](verifier.md) | AC 시나리오, 통합·장애·실기 검증 증거 |

5개는 역할 수이며 동시 실행 수가 아니다. 현재 세션의 4개 슬롯에서는
오케스트레이터 1 + 작업자 최대 3으로 운용한다. 단계별로 역할을 교대하며
코더 본인의 리뷰를 독립 리뷰로 계산하지 않는다. 런타임 한도가 바뀌면 실제 한도를 따른다.
코더는 backend/manager 등 작업별로 나눌 수 있지만 같은 파일의 동시 작성자는 한 명이다.

## 기본 흐름

사용자 → 오케스트레이터 → 조사/계약 확정 → 코딩 → 독립 리뷰 → 수정 → 검증 → 통합 보고.
리뷰 결함에 따른 수정 후에는 관련 리뷰·테스트만 필요한 범위로 반복한다.
병렬 실행은 의존성이 없고 파일 소유권이 겹치지 않는 작업에만 적용한다.

- P0: researcher가 T-00/01 근거를 수집하고 orchestrator가 D-01–05 계약을 정리한다.
  reviewer가 인증·프로토콜·이벤트 계약을 검토하고 verifier가 probe/fixture 기준을 확인한다.
- P1 이후: coder가 승인된 작업 범위를 구현한다. reviewer와 verifier는 실제 diff/결과를 확인한다.
- 역할 배정은 사용자의 기존 작업 범위 안에서 자율적으로 한다. 매 배정마다 허가를 묻지 않는다.
- 사용자에게 필요한 제품 범위·비용·외부 권한 결정은 orchestrator가 선택지와 근거를 정리한다.
  구현상의 일반적인 선택은 스펙과 증거로 해결한다.
- 역할 정의는 배포·외부 메시지 전송·비밀 접근 등 새 권한을 부여하지 않는다.
- 이 문서 작성만으로 P0 조사나 제품 구현을 시작한 것으로 표시하지 않는다.

## 작업 배정 계약

모든 배정에 아래 정보를 포함하고 [작업 상태](../execution.md)에 반영한다.

```text
Task: T-xx / 하위 작업 ID
Role / instance:
Objective:
Spec: PX-xxx, AC-xx, 관련 D-xx
Inputs: 스펙/조사/선행 결과/기준 커밋
Dependencies:
Owned files: 수정 허용 파일 또는 디렉터리
Read-only scope:
Deliverables:
Acceptance / commands:
Constraints / out of scope:
Return to: orchestrator
```

조사/리뷰/검증 역할의 코드는 기본 읽기 전용이다. fixture·검증 문서 수정은
명시적으로 배정한 파일에서만 한다. 범위 밖 수정 필요는 orchestrator에게 보고한다.
공유 workspace에서 다른 작업자의 변경을 덮거나 되돌리지 않는다.
manager 작업 전에는 해당 저장소 지침을 읽고 독립적으로 파일 소유권을 배정한다.

## 결과 보고 계약

```text
Task / role / 기준 커밋 또는 diff:
Status: completed | needs_changes | blocked
Summary:
Changed files:
Evidence: 실행 명령, 결과, 문서 출처, 실기 여부
Findings: 중요도, 파일:줄, 근거, 영향, 권장 조치
Unverified / limitations:
Next dependency:
```

작업자는 통합 완료를 선언하지 않는다. 완료는 orchestrator가 요구사항·독립 리뷰·
검증 증거를 종합하여 판정한다. 근거 없는 '문제 없음', 실행하지 않은 '테스트 통과'를 금지한다.
사용자 보고는 완료한 것, 검증한 것, 남은 위험/결정, 다음 작업으로 요약한다.
