==================================================
WebKillerAI - README (MVP)
==================================================

[DEPS]
- openhtmltopdf (core/pdfbox/slf4j) = 1.0.10
- jsoup = 1.18.3
- slf4j-api = 2.0.13
- (smoke-target https 전용) BouncyCastle bcprov/bcpkix jdk18on = 1.78.1

1) 개요
--------------------------------------------------
- Java 17 / JavaFX 17 기반 **로컬 데스크탑 비파괴 웹 취약점 스캐너**
- 허가된 대상만 스캔하고 **HTML / JSON / (옵션) PDF** 리포트 생성
- JSON 리포트 **v1.2**: 각 이슈에 `requestLine` / `evidenceSnippet` **항상 포함**
- HTML 리포트: “요청 라인 + 스니펫”은 **렌더링 옵션**(수집은 항상 유지)
- **PDF 파이프라인 안정화**: 임시파일 → “%PDF-” 헤더 검증 → 원자 이동(0KB/깨짐 방지)
- **모드**: SAFE / SAFE_PLUS / **AGGRESSIVE_LITE** / **AGGRESSIVE**
  - **AGGRESSIVE = SAFE_PLUS ∪ AGGRESSIVE_LITE** (비파괴: GET/HEAD/OPTIONS)
  - SAFE_PLUS/AGGRESSIVE_LITE에서 일부 **액티브 프로브** 수행
  - **Open Redirect 폴백**: 엔진 미매핑이어도 최소 1회 직접 검증
  - **OR-only 최적화**: redirect/returnUrl/url/next 파라미터 없으면 ActiveRunner 생략

2) 설치 / 빌드
--------------------------------------------------
요구사항
- Gradle 8.9+
- Java 17 (toolchain 권장)
- JavaFX 17

빌드
  ./gradlew clean build

실행(데스크탑 UI)
  ./gradlew :app-desktop:run

의존성 팁
- PDF는 `openhtmltopdf-core / -pdfbox / -slf4j`만 필요.
- **`openhtmltopdf-jsoup-dom` 아티팩트는 없음** — 추가하지 마세요.

3) 사용법(데스크탑 UI)
--------------------------------------------------
기본 실행
  ./gradlew :app-desktop:run

UI 흐름
- **Target URL / Depth** 입력 → Scan
- **Save to**: UI > scan.yml.output.dir > `out/` 우선순위
- **Also save JSON / Also save PDF**: 토글(PDF 렌더러 없으면 비활성화)
- **Open report**: 동일 타임스탬프 **HTML** 우선
- 로그 레벨, 진행률/취소, 검색/필터, Severity 정렬, CSV 내보내기 지원

출력 경로
  out/reports/{host}/scan-{host}--YYYYMMDD-HHmm.{html|json|pdf}

자주 쓰는 시스템 프로퍼티(선택)
  -Dwk.out.dir=outdir
  -Dwk.log.level=INFO
  -Dwk.export.alsoJson=true
  -Dwk.export.pdf=true
  -Dwk.mode=SAFE_PLUS

(HTML Evidence 렌더링)
  -Dwk.report.showEvidenceDetails=on|off   # 표시 토글(SAFE 기본 off, SAFE_PLUS 기본 on)
  -Dwk.html.evi.maxChars=512
  -Dwk.html.evi.clampLines=2

권장 프리셋
- 빠른 훑어보기:   maxChars=512, clampLines=2
- 상세 검토:       maxChars=2048, clampLines=4
- 용량 최소화:     maxChars=256, clampLines=2

4) 코어 구성
--------------------------------------------------
크롤러 / HTTP
- BFS 크롤링(동일 도메인 옵션, maxDepth, 중복 제거, URL 정규화)
- **robots.txt 캐시**: 성공 30분 / 실패 10분, 미존재=허용(allow all)
- Java HttpClient + 재시도(429/5xx/네트워크 오류 최대 3회, Retry-After≤30s)

스캐너 / 액티브
- SignatureScanner: 보안 헤더/HSTS/쿠키 플래그, 서버 5xx, 경량 XSS/SQLi 패턴, 단순 Anomaly
- **ProbeEngine**(단일 진실원): GET(no-redirect) / HEAD / CORS preflight, evidence helpers
- **ActiveScanRunner**: Mixed / OpenRedirect / LFI / SSTI / XSS / SQLi / CORS 실행
  · **Open Redirect 폴백** + **OR-only 최적화** 반영

리포트
- **HTML**: 요약바(Avg/p95/Max), 링크/복사, Evidence 클램프/토글, 위험도 정렬/필터
- **JSON(v1.2)**: `meta.runtime`, `counts.pages`, `meta.scope.excludes`,
  `issues[].riskScore` + `issues[].requestLine` + `issues[].evidenceSnippet` (항상 포함)
- **PDF(옵션)**: openhtmltopdf 기반

5) 모드 정리 (UI 기본 SAFE)
--------------------------------------------------
- **SAFE**: 패시브 중심(보안 헤더/서버 에러/경량 시그니처). GET/HEAD, 낮은 RPS
- **SAFE_PLUS**: XSS(Reflected) / SQLi(Error) / CORS / Open Redirect
  · onQueryOnly=**true**(기본)
- **AGGRESSIVE_LITE**: LFI(Path Traversal) / SSTI(Simple) / Open Redirect / Mixed Content*
  · onQueryOnly=**false**(기본)
  · *Mixed는 **HTTPS** 문서에서만 의미
- **AGGRESSIVE**: SAFE_PLUS ∪ AGG_LITE(둘 다 수행, 비파괴)

6) 액티브 게이트/튜닝 (필요 시만)
--------------------------------------------------
글로벌
- -Dwk.active.onQueryOnly=true|false
- -Dwk.active.firstPages=50
- -Dwk.active.sample=1.0
- -Dwk.active.max=400
- -Dwk.active.maxPerHost=60
- -Dwk.active.rps=3

프로필별(우선)
- wk.safeplus.activeOnQueryOnly / activeFirstPages / sample / rps / maxActive / maxActivePerHost
- wk.agglite.activeOnQueryOnly  / activeFirstPages / sample / rps / maxActive / maxActivePerHost
- wk.aggressive.activeOnQueryOnly / activeFirstPages / sample / rps / maxActive / maxActivePerHost

FeatureMatrix 기본값(요약)
- maxParamsPerUrlDefault: SAFE=0, SAFE_PLUS=3, AGG_LITE=4, AGGRESSIVE=6
- activeDefaultRps(대략): SAFE_PLUS ≤3, AGG_LITE ≤5, AGGRESSIVE ≤7

7) 스모크 타깃(내장 데모 서버)
--------------------------------------------------
모듈: `:smoke-target` (HTTP/HTTPS 간이 서버)

실행
  ./gradlew :smoke-target:run
  • HTTP : http://localhost:8080
  • HTTPS: https://localhost:8443  (자가서명 p12 자동 생성/로드)

엔드포인트
- /mixed  : (HTTPS일 때만) Mixed Content 유도
- /redir  : Open Redirect(Location 반영)
- /file   : LFI(Path Traversal) 스모크
- /ssti   : 간이 SSTI(“{{7*7}}WKAI” → “49WKAI” 치환)
- /cors   : Access-Control-Allow-* 취약 사례
- /echo   : 반사 에코(Reflected XSS 스모크)
- /prod   : SQLi 오류 기반 스모크

기대 탐지(샘플)
- SAFE_PLUS: /prod?id=' → SQLi, /cors → CORS, /redir → Open Redirect
- AGG_LITE:  /file?file=../../../../etc/passwd → LFI, /ssti?q=... → SSTI, /mixed(HTTPS) → Mixed
- AGGRESSIVE: 위 두 세트 전체

⚠ 브라우저에서 https 접속 시 **자체서명 경고는 정상**. 스캔/기능엔 영향 없음.

8) Risk 요약 계산
--------------------------------------------------
- Avg: riskScore 평균(null 제외)
- p95: 95% 분위
- Max: 최댓값
- riskScore 미지정 시 severity 매핑: INFO=10, LOW=25, MED=50, HIGH=75, CRITICAL=90

9) 제한 사항
--------------------------------------------------
- 전 모드 **비파괴(GET/HEAD/OPTIONS)** — 상태변경 취약점 일부 미탐 가능
- 인증/SPA/비표준 응답 편차에 따른 누락 가능, WAF/봇 차단 영향
- **PDF CSS 제약**: openhtmltopdf는 CSS 서브셋만 지원 → HTML 기준 확인 권장
- 스모크 서버의 보안 헤더 누락은 **테스트 용도**(패시브 감지 확인 목적)

10) 성능 팁
--------------------------------------------------
- Depth 보수적 설정(1~3)
- Concurrency/RPS 동시 조절(예: cc=4, rps=7 근방)
- SAFE_PLUS는 파라미터 많은 사이트에서 느릴 수 있음 → exclude/샘플/예산 게이트 활용
- robots 캐시: 성공 30분 / 실패 10분
- OR-only 최적화로 불필요한 액티브 호출 최소화

11) 문제 해결(Troubleshooting)
--------------------------------------------------
- PDF 0KB/열리지 않음: 임시→검증→원자 이동 경로로 0KB 남지 않음(실패 로그 확인)
- PDF 렌더러 미탑재: UI의 PDF 체크박스 비활성화
- 의존성 오류(openhtmltopdf-jsoup-dom): **없는 아티팩트** — 의존성에서 제거
- 폰트/아이콘: 시스템 폰트 사용(특수 글꼴은 임베드 확장 필요)

(수동 PDF 스모크)
  hexdump -C out/reports/*/scan-*.pdf | head -n1   # "%PDF-"
  wc -c out/reports/*/scan-*.pdf                    # > 1KB

12) scan.yml 최소 예시
--------------------------------------------------
target: "https://example.com"
scope:
  sameDomainOnly: true
  maxDepth: 2
  excludePaths:
    - "/admin/**"
    - "re:^/debug\\-.*"
mode: "SAFE"    # UI 기본 SAFE. UI에서 SAFE_PLUS/AGG_LITE/AGGRESSIVE 선택 가능(또는 -Dwk.mode)
timeoutMs: 8000
concurrency: 4
followRedirects: true
output:
  dir: "out"
  alsoJson: true
  format: "html,json"  # 필요 시 "pdf" 포함

13) Roadmap — v0.4 (예고)
--------------------------------------------------
- AGGRESSIVE 페이로드 강화(XSS/SQLi/SSTI 딕셔너리 확장, 제한적 POST-echo 옵션)
- Smoke 확장(LFI 윈도우 변형, SSTI/OR/CORS 바리에이션)
- ProbePlan 스냅샷 단위 테스트
- HTTPS 스모크 케이스 보강(Mixed/보안헤더 조합)
