WEBKILLERAI — Robots 처리 스펙 (v0.3, 2025-08-28)
==================================================

목적
--------------------------------------------------
- 스캐너의 안전한 크롤링 범위를 일관되게 보장하기 위한 robots.txt 해석 규칙을 명문화한다.
- 구현 모듈: core/crawler/robots/{RobotsCache,RobotsPolicy}.java (+ Crawler.java 연동)

적용 범위
--------------------------------------------------
- HTTP/HTTPS 대상만 적용
- sameDomainOnly=true 일 때만 하위 경로 탐색 (서브도메인은 별도 호스트로 간주)
- 요청 메서드: GET/HEAD (SAFE 모드)

User-Agent / 식별
--------------------------------------------------
- 기본 UA: "WebKillerAI" (대소문자 무시하여 비교)
- 매칭 우선순위: "WebKillerAI" 섹션 → "*" 섹션 → 그 외 섹션은 무시
- 동일 UA가 여러 그룹에 있으면 병합 후 하나의 규칙 집합으로 평가

robots.txt 페치 규칙
--------------------------------------------------
- URL: {scheme}://{host}:{port}/robots.txt (port는 명시된 경우만 포함)
- Redirect: 최대 3회(3xx)까지 추적, **동일 호스트만 허용**, 스킴 전환(http↔https) 허용
- 크로스-호스트 리다이렉트는 실패 처리 → allow-all
- 타임아웃: connect 2s / read 3s
- 인코딩: HTTP 헤더 charset 우선, 없으면 UTF-8 (BOM 허용)
- 실패 처리:
  - 네트워크/서버 오류(5xx/타임아웃/4xx except 404/410): "allowAll"
  - 404/410: 규칙 없음으로 간주 → allow-all
- 캐시 키: scheme + host + port
- TTL:
  - 성공(2xx): 30분
  - 실패(404/410/5xx/네트워크): 10분 (allow-all 유지)
- 캐시 저장: in-memory (프로세스 로컬), LRU 128 엔트리 (최신 호스트 우선)

URL 정규화
--------------------------------------------------
- 입력 URL → 정규화 후 robots 매칭에 사용
  - 쿼리/프래그먼트 제거
  - 호스트 소문자, 기본 포트 제거 (http:80 / https:443)
  - path: 빈 경로는 "/" 로 통일, "//"는 단일 "/"로 축약
  - 퍼센트 인코딩은 디코드하지 않음, HEX는 대문자로 정규화 ("%2f" → "%2F")
- 매칭 대상 문자열: rawPath (쿼리·프래그먼트 제외)

디렉티브 파싱
--------------------------------------------------
- 주석 "#" 및 공백 라인 무시
- 레코드 단위: User-agent 라인으로 시작, 다음 User-agent 또는 빈 줄 전까지의 블록
- 지원 지시자(대소문자 무시): User-agent, Allow, Disallow
- Crawl-delay, Sitemap 등 알 수 없는 디렉티브는 무시
- 빈 Allow/Disallow 값은 무시(규칙 없음)

패턴/매칭 규칙
--------------------------------------------------
- 기본은 접두(prefix) 매칭
- 와일드카드 "*": 길이 0+ 문자 일치, "/" 포함
- 끝 앵커 "$": 경로 끝과 일치
- 예시:
  - Disallow: /private*       → "/private", "/private123", "/private/x" 차단
  - Allow   : /private$       → 정확히 "/private"만 허용
  - Disallow: /api/*/debug$   → "/api/v1/debug" 금지, "/api/v1/debug/x" 허용
- 경로 매칭은 대소문자 구분
- 비정상 패턴(공백, 역슬래시 등)은 무시

선정/우선순위 (Longest-Match, Allow-Wins)
--------------------------------------------------
1) 요청 path와 매칭되는 모든 규칙 중 가장 긴 패턴 길이를 가진 규칙 선택
2) 동일 길이 충돌 시 Allow 우선
3) 매칭 규칙 없으면 허용
4) 내부 excludePaths(ScanConfig)와 충돌 시 excludePaths가 최우선(차단)

예외/가드레일
--------------------------------------------------
- 파일 크기: 최대 512KB
- 규칙 수: 최대 1000
- 너무 큰 파일/규칙 초과 시 → allow-all (경고 로그)
- Redirect 루프 → allow-all

동시성/성능
--------------------------------------------------
- 동일 호스트 robots 병행 페치 방지 (single-flight)
- 매치 연산: 규칙 수 N에 대해 O(N)

로그/옵저버빌리티
--------------------------------------------------
- 레벨: DEBUG(매칭 상세), INFO(요약), WARN/ERROR(실패)
- 페치 로그: host, status, fromCache, ageSec, bytes
- 매칭 로그(옵션): path, decision(ALLOW/DISALLOW), winnerPattern, matchLen

scan.yml 설정 키 (예시)
--------------------------------------------------
crawler:
  respectRobots: true
  robotsTtlMinutes: 30
  robotsFailTtlMinutes: 10
  robotsMaxRedirects: 3
  robotsTimeoutMs: 3000
  robotsUa: "WebKillerAI"
  robotsFallbackAllowAll: true
excludePaths:
  - "/admin"
  - "*/*logout*"
  - "re:\\?.*token=.+"

의사코드
--------------------------------------------------
function isAllowed(url, ua="WebKillerAI"):
  if isExcludedByConfig(url.path): return DENY
  robots = RobotsCache.get(url.host)
  if robots == null or expired: robots = fetchRobots(url.host)
  if robots.fetchFailed: return ALLOW
  rules = rulesFor(ua) or rulesFor("*")
  if rules.isEmpty(): return ALLOW
  best = null
  for rule in rules:
    if match(url.path, rule.pattern):
      if best == null or rule.len > best.len:
        best = rule
      else if rule.len == best.len and rule.type == ALLOW and best.type == DISALLOW:
        best = rule
  if best == null: return ALLOW
  return best.type == ALLOW
