# WebKillerAI 베타 (Windows Portable)

1) ZIP 해제  
2) `WebKillerAI/start.cmd` 더블클릭  
3) 허가된 타깃만 스캔 부탁드립니다 🙏

## 피드백
- OS/모드/타깃/깊이/옵션
- `out/reports/*/scan-*.json`
- `out/logs/app.log` (있으면)

**SHA256:** `9631D9CA394ACC65BF0F353E5B986DF1651DD665579F40D9C9CB9ACBC76DFA26`  
**다운로드:** [Releases](../../releases)

---

## 개요

**WebKillerAI** 는 Java 17 / JavaFX 기반의 **로컬 데스크탑 비파괴(READ-ONLY) 웹 취약점 스캐너**입니다.  
허가된 대상만 스캔하며 **HTML / JSON / (옵션) PDF** 리포트를 생성합니다.  
모든 이슈에 대해 **`requestLine` + `evidenceSnippet`**(±80자) 증거를 수집합니다.

- **비파괴 원칙:** `GET / HEAD / OPTIONS`만 사용 (POST/PUT/DELETE 없음)
- **대상 범위:** 동일 도메인 옵션, BFS 크롤링, robots.txt 캐시/존중
- **리포트 포맷:** HTML(토글 Evidence), JSON(v1.2), PDF(openhtmltopdf)

---

## 모드 차이

- **SAFE**  
  - 패시브만: 보안 헤더/쿠키, 서버 에러, 경량 시그니처  
  - 가장 안전/빠름

- **SAFE_PLUS**  
  - 액티브: **XSS(Reflected)**, **SQLi(Error)**, **CORS**, **Open Redirect**  
  - 파라미터가 있는 URL 위주(onQueryOnly)

- **AGGRESSIVE_LITE**  
  - 액티브: **LFI(Path Traversal)**, **SSTI(Simple)**, **Open Redirect**, **Mixed Content**  
  - Mixed는 **HTTPS 문맥에서만** 의미

- **AGGRESSIVE**  
  - **SAFE_PLUS ∪ AGG_LITE**(모두 수행)  
  - 여전히 **비파괴(GET/HEAD/OPTIONS)**

> 전 모드 공통: 모든 이슈에 **requestLine + evidenceSnippet**(±80자) 수집.

---
## 탐지 항목 & 신호 

- **XSS (Reflected / SAFE_PLUS)**: 비이스케이프 반사(HTML/JS/URL 컨텍스트)
- **SQLi (Error / SAFE_PLUS)**: DB 오류 토큰(SQLSTATE/ORA/MySQL 등) 노출
- **CORS 오구성 (SAFE_PLUS)**: `ACAO:"*"` + `ACAC:true` 등 위험 조합
- **Open Redirect (SAFE_PLUS / AGG_LITE)**: 3xx + `Location`이 외부 도메인
- **LFI / Path Traversal (AGG_LITE)**: `../../../../etc/passwd` → `root:x:` 등 토큰
- **SSTI (Simple / AGG_LITE)**: `{{7*7}}` / `${7*7}` / `<%=7*7%>` → 49 또는 템플릿 에러
- **Mixed Content (AGG_LITE)**: **HTTPS** 문서 내 `http://` 서브리소스 참조
- **보안 헤더/쿠키 (ALL)**: HSTS/CSP/XFO/CTO/Referrer-Policy/Permissions-Policy, Secure/HttpOnly/SameSite 등

---

## 빠른 시작 (Portable ZIP)

1. 릴리스에서 ZIP 다운로드 → 압축 해제  
2. `WebKillerAI/start.cmd` 더블클릭 (설치/관리자 권한 불필요)  
3. UI에서 **Target URL / Depth** 입력 → **Scan**  
4. 리포트 열기(HTML 우선) 또는 `out/reports/{host}/` 폴더에서 확인

---

##알려진 제한(베타)

인증/세션 자동화, 폼 제출/파일 업로드, Blind/Time-based SQLi, SSRF/XXE, RCE, DoS 등 범위 외
전 모드 비파괴 → 상태변경 취약점 일부 미탐 가능
SPA/비표준 응답, WAF/봇 차단 환경에서 편차 가능

---

##라이선스

LICENSE 파일 참조 (미지정 시 추후 업데이트)
