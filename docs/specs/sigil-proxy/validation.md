# T-03 검증 준비와 D-04 제안

2026-09-27 · verifier/coder · 기준 HEAD `24eddb2` 위에서 작성, `97db268`로 커밋. fixture revision 2025-11-25는 D-01 잠정 지원 revision과 일치(2026-10-10).
상태: **독립 fixture 준비 검증 완료; protocol 후보는 T-01 대기**.
Production proxy, 실제 vendor client, server/manager E2E 및 성능 측정은 미실행이다.
이 문서는 D-04 권고안이며 확정/출시 승인이나 P1 인수 통과 선언이 아니다.
복구 dispatch에서는 기존 Python 파일을 보존하고 README와 본 문서만 작성했다.

## 후보와 근거

선택한 fixture revision은 MCP `2025-11-25` Streamable HTTP이다.
2026-09-27에 공식 [transport 명세](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)와
[tools 명세](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)를 확인했다.
JSON/SSE 응답, initialized 알림의 빈 202, 세션/버전 헤더, 페이지 도구 목록과
`isError` 결과를 좁은 fixture 범위로 구현했다. 명세 열람은 제품 실기 검증이 아니다.
현재 제품/SDK 지원 표와 최신 revision 선택, 설정·권한·hook·무인 실행·OS 동작은
T-01 조사 책임이며 여기서 추정하거나 compatibility gate를 변경하지 않는다.

## 재현과 실제 결과

[fixture README](../../../scripts/proxy-p0/README.md)에 실행/종료 절차가 있다.
Python stdlib만 사용하고 매 실행 `127.0.0.1:0`에 bind한다. smoke는 외부 endpoint를
받지 않으며 환경 proxy, credentials 또는 실제 MCP를 사용하지 않는다.

실행 환경: macOS 26.6.2 build 25G83, Darwin 25.6.0, arm64, Python 3.14.6.
측정 일자: 2026-09-27. 실제 실행 명령과 stdout:

```text
$ python3 -B scripts/proxy-p0/smoke.py
PASS initialize + initialized notification; candidate=2025-11-25
PASS tools/list: pages=2 tools=4 complete=true
PASS tools/call: JSON, SSE multiline/CRLF, deliberate isError=true
PASS accepted-call drop: outcome=unknown client_attempts=1 fixture_invocations=1
PASS total_invocations=4; no automatic retry in this runner
ENV Python=3.14.6 system=Darwin release=25.6.0 machine=arm64
LIMIT fixture-only; no proxy, vendor client, throughput measurement, or release acceptance
```

Exit 0. 독립 self-test 명령:

```text
$ python3 -B -m unittest discover -s scripts/proxy-p0 -p 'test_*.py' -v
Ran 14 tests in 6.123s
OK
```

Exit 0, 14개 모두 통과. 위 시간은 unittest 실행 시간이며 처리량 벤치마크가 아니다.
테스트는 JSON/SSE/도구 오류, 두 페이지/잘못된 cursor, drop과 중복 계수,
잘못된 인자·메시지·크기·헤더, 세션 삭제/초기화, 지원하지 않는 기능,
SSE comment/CRLF/multiline 및 잘린/과대 stream을 확인했다.

## AC 추적 및 판정 경계

| 요구사항 / AC | 이번 fixture 증거 | Proxy 인수 상태 / 남은 검증 |
|---|---|---|
| PX-001 / AC-14 | 관련 production 경로 없음(fixture는 별도 Python 스크립트이며 설치 경로가 아님) | not_run: 개인 설치 기본 옵션에서 proxy 미활성·미listen, 명시적 `--config` 없이는 미기동 |
| PX-002–004 / AC-01 | initialize, tools capability, JSON/SSE 왕복 PASS | not_run: 실제 client → proxy → MCP → server → manager 호출 ID 연결 |
| PX-005 / AC-02 | 두 페이지 전체 목록과 잘못된 cursor PASS | not_run: baseline/drift, 접근 scope 차이, 중간 page 실패 시 삭제 방지 |
| PX-006,015 / AC-03 | 수락 후 socket drop, unknown 분류, client 1회/fixture 1회 PASS | not_run: proxy 전달/감사 상태와 자동 재실행 금지 |
| PX-003,013 / AC-07 | 세션/버전, finite SSE, fixture 크기 제한 PASS | not_run: 취소, resume, 서버 요청, 큰 응답, 동시성 및 production 한도 |
| PX-002,014 / AC-08 | loopback bind, Host/Origin 거절 PASS | not_run: 요청의 upstream 지정 무시, proxy SSRF, IPv6, DNS rebinding, redirect 목적지 정책 |
| PX-003–004 / AC-15 | fixture가 지원하지 않는 기능을 거절하는 시험만 PASS(proxy 아님) | not_run: support-matrix.md §5 각 행의 응답·upstream 호출 수·감사 기록; undecided 행 해소 |
| PX-007–011,016 / AC-04–06,12 (PX-008 원격 설정 TTL 만료 포함) | 관련 production 경로 없음 | not_run: principal 격리, canary, spool/중앙 단절·복구·재시작 |
| PX-013 / AC-12 | fixture 크기 제한 PASS(AC-07과 공유, production 한도 아님) | not_run: spool 용량·디스크 가득 참·재시작·backpressure·정상 종료 |
| PX-012 / AC-01,13 | 관리 API 없음 | not_run: server/manager 권한과 관리 변경 감사 |

counter는 drop 도구를 수락한 직후 lock 안에서 증가하며 응답 전 연결을 끊는다.
동일 request ID를 다시 전송해도 계수하므로 deduplication으로 retry를 숨기지 않는다.
이 증거는 **이번 smoke runner의 자동 retry 없음**만 입증한다. 외부 부작용의 실행,
지연된 vendor retry, proxy의 at-most-once 또는 exactly-once를 입증하지 않는다.
직접 fixture 접근과 별도 counter는 테스트 oracle이며 제품 감사 API가 아니다.

## D-04 권고: 첫 배포와 수치 한도 후보

첫 production 검증 대상은 **Rocky Linux 9 단일 proxy 프로세스**로 확정했다(2026-10-10 사용자 결정, [decisions.md](decisions.md) D-04).
RHEL 계열 기준으로 SELinux enforcing과 rpm 배포를 포함해 검증한다. 초기 권고안(Ubuntu 24.04 LTS x86_64)은 대체되었다.
macOS arm64는 현재 fixture 개발 환경일 뿐 production 검증 대상 확정 근거가 아니다.
아래 값은 보수적 P1 초기값 제안이며 구현/측정 전이다. 설정 이름은 T-02 계약에 맞춘다.
단위 MiB/GiB는 2진 단위이며 압축 사용 시 decoded 크기도 제한한다.

| 대상 | 제안 기본 한도 | 초과/장애 시 제안 동작 |
|---|---|---|
| HTTP request body / header | 1 MiB / 32 KiB | upstream 전달 전 413 / 431; 원문 로그 금지 |
| 단일 JSON 응답 / SSE event | 8 MiB / 1 MiB | bounded parser로 종료; 이미 전달한 호출은 outcome unknown 가능 |
| 호출별 응답 누적 / 대역폭 | 64 MiB / 4 MiB/s | 누적 초과 종료, 속도는 backpressure; 무한 buffer 금지 |
| 프로세스 응답 대역폭 | 32 MiB/s | 공유 제한; 느린 reader도 bounded buffer 유지 |
| 동시 호출 | 전체 64, route 16, principal 8 | 새 호출 429, 자동 tool retry 없음; 활성 SSE도 1개로 계수 |
| 활성 세션 | 전체 256, principal 32; idle 15분 | 초기화 거절/idle 만료; 활성 호출을 idle로 보지 않음 |
| 대기 queue | 기본 0 | 과부하 즉시 거절; 숨은 무제한 대기 금지 |
| connect / response idle / 호출 전체 | 5초 / 30초 / 120초 | 단계별 timeout; upstream 전송 후에는 미실행으로 단정 금지 |
| 종료 grace | 30초 | 새 수락 중단, 진행 호출 drain; 잔여 호출 불명/감사 복구 |
| tool inventory | 100 page, 10,000 tool, 총 16 MiB | 불완전 snapshot 표시; baseline 삭제 판단 금지 |
| 감사 event / spool | event 16 KiB, spool 1 GiB + 별도 gap reserve 16 MiB | 80% degraded, 100% 기본 새 호출 중단; 기존 in-flight 완료 기록용 여유 설계 |
| spool 보관 | 미전송 event 자동 만료 없음; ack 이후 24시간 보관 상한 | 공간 부족 시 ack된 자료부터 정리, 미전송 자료 삭제로 정상처럼 보이지 않음 |
| 프로세스 resource budget | steady RSS 256 MiB 목표, cgroup memory.max 512 MiB, CPU 2 core | hard kill 복구 시험 필수; 상한 도달 전에 admission/backpressure |

fixture 자체의 64 KiB/3초 제한과 위 production 후보를 혼동하지 않는다.
스풀 reservation은 동시 in-flight 호출의 terminal event 수용까지 계산해야 한다.
시간/응답 한도 종료는 upstream 부작용을 취소하지 않으며 감사 전송 retry와 도구
실행 retry를 분리한다. 실측 전에 이 값을 지원 보장으로 게시하지 않는다.

## P1 성능 시험 환경과 합격 목표 제안 (미측정)

고정 환경: Rocky Linux 9(SELinux enforcing), 4 vCPU/8 GiB RAM/40 GiB SSD VM, 아키텍처를 결과에 명시(aarch64·x86_64는 서로 다른 baseline),
proxy에 2 vCPU/512 MiB cgroup, release build, 동일 host의 합성 upstream과 load driver.
upstream과 driver는 남은 CPU에 배치하고 CPU 모델/주파수 정책, hypervisor,
kernel, Rust/compiler/dependency lock, commit, filesystem, TLS 설정과 모든 limits를
결과에 기록한다. 가용 환경이 다르면 같은 표의 새 baseline으로 명시하고 섞지 않는다.
성능용 synthetic load server/driver는 별도 준비가 필요하며 이 Python smoke를
성능 서버로 사용하지 않는다. Proxy hot path 비교와 TLS 배포 비교를 별도 측정한다.

1. direct client → fixture와 client → proxy → 같은 fixture를 교대로 실행한다.
   P1 audit/spool은 켜고 local control-plane collector를 붙인다. 중앙 단절은 별도 run이다.
2. synthetic 1 KiB request/4 KiB JSON response로 concurrency 1/8/32/64,
   30초 warm-up + 300초 측정, 각 조건 3회 수행한다. 100 calls/s 고정 offered load도
   측정하고 최대 sustainable throughput은 별도 sweep으로 관찰한다.
3. 1 MiB request/8 MiB JSON response 경계와 limit+1 거절, 32개 SSE 각 60초,
   초당 1 KiB event, slow reader, 65개 동시 호출 및 principal별 포화를 시험한다.
   동일 부하의 direct baseline을 함께 기록한다.
4. 중앙 10분 단절, spool fill, grace 종료/강제 재시작, accepted-call drop을 별도 수행한다.
   spool은 시험용 임시 디렉터리에 한정하고 운영 디스크나 실제 credentials를 쓰지 않는다.
5. 요청별 latency 분포와 p50/p95/p99, 실패/거절율, completion rate, CPU,
   최대 RSS, 열린 FD, 활성 연결, queue/buffer, spool bytes/event를 기록한다.
   direct/proxied 분위수 차이는 비교 지표이며 개별 요청 지연 차이로 해석하지 않는다.

후보 합격 목표: 작은 JSON 100 calls/s, concurrency 32에서 direct 대비 추가
p50 ≤ 2 ms / p95 ≤ 10 ms / p99 ≤ 25 ms, 예상 밖 오류 0, 정상 부하 거절 0,
steady RSS ≤ 256 MiB, 모든 run RSS < 512 MiB. 32개 SSE의 event delivery 추가
p95 ≤ 20 ms, 종료 후 연결/메모리 증가가 누적되지 않을 것. 최대 처리량 값은
측정 결과로 보고하며 이 목표를 현재 throughput으로 주장하지 않는다.
한도/장애 run의 예상 거절은 정상 부하 오류율과 분리해 보고한다.

D-04는 orchestrator가 OS·limits·위 목표를 수락하고 T-01 지원 범위를 결합해
고정할 것을 권고한다. P1 출시에는 위 측정 결과, 실제 vendor client 1종 이상,
proxy/server/manager E2E, 독립 리뷰, AC 전체 결과가 추가로 필요하다.
