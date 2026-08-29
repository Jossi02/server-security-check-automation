# Project Notes

## 공개 범위

이 저장소는 2025년 네트워크보안 수업의 2인 팀 프로젝트에서 공개 가능한 소스만 선별한 역사적 산출물이다.

- 원본 보고서와 PPT는 팀원 이름·학번 등 과제 제출용 개인정보가 있어 제외했다.
- 저장소 소유자는 스크립트 대부분 구현, 공통 흐름/출력 정리, 보고서 공동 작성, 발표자료 제작에 참여했다.
- 생성형 AI는 코드 초안·수정·검토의 보조 도구로 사용했다.
- 단독 구현으로 주장하지 않으며, 공개에 대한 팀원의 동의를 받았다.
- 임의의 라이선스를 추가하지 않았다.

## 가이드 버전

기존 파일명은 2025년 수업 당시 항목 번호를 보존한다. KISA가 2025-12-24 게시한 최신 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」(통상 2026 가이드)는 항목 번호와 구조가 바뀌었다.

| 기존 | 현재 매핑 | 주의 |
|---|---|---|
| U-52 | U-10 | 동일 UID 계정 |
| U-57 | U-31 | 홈 디렉터리 소유자/권한 |
| U-61 | U-54 | 비암호화 FTP 비활성화와 가장 가까운 개념 |
| W-50 | W-09 하위 요소 | 최대 암호 사용 기간만 다루며 W-09 전체가 아님 |
| W-62 | W-31 | SNMP 접근 통제 |
| W-71 | W-43 | 이벤트 로그 파일 접근 제한 |

따라서 이 저장소는 “2026 KISA compliant”가 아니라 **historical course artifact + current mapping + retested behavior**로 설명한다.

## 2026-08-29 공개 전 정적 감사

- U-52: 수동 조치를 실패로 기록하던 상태 의미, 안전하지 않은 출력, 미검증 TTP를 수정했다.
- U-57: 잘못된 `AC-3`, `eval`, `fixed=yes`, 성공 확인 없는 chmod/chown을 제거하고 detect-only/manual로 바꿨다.
- U-61: `ss` 헤더 오탐을 막고 읽지 않은 설정 파일 주장을 제거했다. 설치된 모든 FTP unit을 변경하던 자동 조치/불완전 rollback은 제거하고 detect-only/manual로 바꿨다.
- W-50: 명령·파싱 실패를 `ERROR/Unknown`으로 분리하고 관리자/백업/명령 성공/재조회 검증을 추가했다. 로컬 정책 한계를 명시했다.
- W-62: PowerShell 메타데이터가 아니라 실제 registry value names/values만 센다. 승인된 manager 주소를 알 수 없으므로 자동 localhost 조치는 제거했다.
- W-71: 모든 Everyone ACE가 아니라 Everyone의 `Allow` ACE 중 write-sensitive rights만 탐지한다. 전체 ACL 자동 변경과 SDDL 텍스트 기반 rollback 주장은 제거했다. 전체 effective access 계산은 하지 않는다.
- 현재 tip을 자격증명 형식 위주로 재검색했으며 실제 토큰·개인키·클라우드 키 값은 발견하지 못했다. `password/passwd` 문자열은 정책명과 시스템 파일 경로였다.

## 검증 경계

자동화된 검증은 정적·비파괴 범위로 제한한다.

- `bash -n`, ShellCheck
- PowerShell parser, PSScriptAnalyzer
- fixture 기반 U-52 UID 탐지와 W-50 한/영 `net accounts` 파싱

다음은 disposable VM에서만 수동 검증한다.

- Linux: 중복 UID 시나리오, 홈 디렉터리 소유권/권한 시나리오, systemd/socket/inetd/port 21 조합
- Windows: 관리자/비관리자 `net accounts`, 백업·설정·재조회·rollback, 로컬 정책과 도메인 정책의 차이
- Windows: 실제 SNMP registry value 조합과 서비스 상태
- Windows: 상속된 Allow/Deny ACE와 여러 principal을 포함한 Event Log 경로의 effective access

운영 환경 적용, 최신 가이드 전체 준수 판정, 모든 Linux/Windows 버전 호환성은 이 저장소의 검증 범위가 아니다.
