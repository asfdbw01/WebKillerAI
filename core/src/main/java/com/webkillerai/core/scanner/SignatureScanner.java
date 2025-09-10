package com.webkillerai.core.scanner;

import com.webkillerai.core.api.IScanner;
import com.webkillerai.core.model.HttpResponseData;
import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import com.webkillerai.core.util.SeverityWeights;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 시그니처 기반 간단 징후 스캐너 + 경량 Anomaly 레이어 */
public class SignatureScanner implements IScanner {

    // --- SQLi 오류 패턴(대표적 DB 에러 문구) ---
    private static final Pattern SQLI_ERROR = Pattern.compile(
            "(?i)(you have an error in your sql syntax|warning:\\s*mysql|ora-\\d{5}|sqlstate|syntax error at or near|unclosed quotation mark after the character string)",
            Pattern.DOTALL);

    // --- XSS 테스트 흔적(아주 단순한 케이스) ---
    private static final Pattern XSS_ECHO = Pattern.compile("(?i)<script[^>]*>[^<]*\\balert\\s*\\(\\s*1\\s*\\)", Pattern.DOTALL);

    // --- Anomaly: 스택트레이스/예외 토큰 ---
    private static final Pattern P_STACKTRACE = Pattern.compile(
            "(?is)(\\bException\\b|\\bTraceback\\b|\\bat\\s+(?:com|org)\\.[A-Za-z0-9_.$]+\\()"
    );

    // --- Anomaly: 응답 크기 변동(±25%) ---
    private static final double SIZE_DELTA_THRESHOLD = 0.25;
    private static final int SIZE_MIN_BASELINE = 16;

    private static final class SizeStat {
        long count;
        long avgLen;
    }
    private final ConcurrentHashMap<String, SizeStat> sizeStats = new ConcurrentHashMap<>();

    @Override
    public List<VulnResult> scan(HttpResponseData resp) {
        List<VulnResult> out = new ArrayList<>();
        URI url = resp.getUrl();
        Map<String, List<String>> headers = resp.getHeaders();
        String body = resp.getBody() == null ? "" : resp.getBody();

        // 1) 서버 오류 5xx
        if (resp.getStatusCode() >= 500 && resp.getStatusCode() <= 599) {
            out.add(VulnResult.builder()
                    .url(url)
                    .issueType(IssueType.SERVER_ERROR_5XX)
                    .severity(Severity.MEDIUM)
                    .description("서버가 5xx 오류를 반환했습니다.")
                    .evidence("status=" + resp.getStatusCode())
                    .confidence(0.7)
                    .riskScore(SeverityWeights.toRisk(Severity.MEDIUM))
                    .requestLine(ProbeEngine.requestLine("GET", url))
                    .evidenceSnippet(snippet(body, null))
                    .build());
        }

        // 2) SQLi 의심(오류 페이지 내 DB에러 문구)
        if (SQLI_ERROR.matcher(body).find()) {
            out.add(VulnResult.builder()
                    .url(url)
                    .issueType(IssueType.SQLI_PATTERN)
                    .severity(Severity.HIGH)
                    .description("SQL 오류 문구가 응답 본문에서 발견되었습니다.")
                    .evidence("matched=SQLI_ERROR")
                    .confidence(0.85)
                    .riskScore(SeverityWeights.toRisk(Severity.HIGH))
                    .requestLine(ProbeEngine.requestLine("GET", url))
                    .evidenceSnippet(snippet(body, "sql"))
                    .build());
        }

        // 3) XSS 흔적(아주 단순한 alert(1) 스크립트)
        if (XSS_ECHO.matcher(body).find()) {
            out.add(VulnResult.builder()
                    .url(url)
                    .issueType(IssueType.XSS_PATTERN)
                    .severity(Severity.MEDIUM)
                    .description("XSS 테스트로 보이는 스크립트 흔적이 감지되었습니다.")
                    .evidence("matched=XSS_ECHO")
                    .confidence(0.6)
                    .riskScore(SeverityWeights.toRisk(Severity.MEDIUM))
                    .requestLine(ProbeEngine.requestLine("GET", url))
                    .evidenceSnippet(snippet(body, "alert(1)"))
                    .build());
        }

        // 4) 보안 헤더 점검
        boolean hasXcto = hasHeader(headers, "x-content-type-options");
        boolean hasXfo  = hasHeader(headers, "x-frame-options");
        boolean hasCsp  = hasHeader(headers, "content-security-policy");
        boolean hasHsts = hasHeader(headers, "strict-transport-security");
        boolean hasRefp = hasHeader(headers, "referrer-policy");

        if (!hasXcto) out.add(missingHeader(url, "X-Content-Type-Options"));

        // XFO 단독 미설정도 Low로 보고(예전 동작 복원)
        if (!hasXfo) {
            out.add(VulnResult.builder()
                    .url(url)
                    .issueType(IssueType.MISSING_SECURITY_HEADER)
                    .severity(Severity.LOW)
                    .description("X-Frame-Options 헤더가 설정되어 있지 않습니다.")
                    .evidence("missing=X-Frame-Options")
                    .confidence(0.75)
                    .riskScore(SeverityWeights.toRisk(Severity.LOW))
                    .requestLine(ProbeEngine.requestLine("GET", url))
                    .evidenceSnippet("")
                    .build());
        }
        // XFO와 CSP 둘 다 없으면 클릭재킹 방어 부재 안내
        if (!hasXfo && !hasCsp) {
            out.add(VulnResult.builder()
                    .url(url)
                    .issueType(IssueType.MISSING_SECURITY_HEADER)
                    .severity(Severity.LOW)
                    .description("클릭재킹 방어 부재(X-Frame-Options 또는 CSP frame-ancestors).")
                    .evidence("X-Frame-Options/CSP(frame-ancestors) not found")
                    .confidence(0.7)
                    .riskScore(SeverityWeights.toRisk(Severity.LOW))
                    .requestLine(ProbeEngine.requestLine("GET", url))
                    .evidenceSnippet("")
                    .build());
        }

        // CSP 약함(unsafe-inline / unsafe-eval)
        String cspValue = firstHeaderValue(headers, "content-security-policy");
        if (cspValue != null) {
            String lc = cspValue.toLowerCase(Locale.ROOT);
            if (lc.contains("'unsafe-inline'") || lc.contains("'unsafe-eval'")) {
                out.add(VulnResult.builder()
                        .url(url)
                        .issueType(IssueType.WEAK_CSP)
                        .severity(Severity.MEDIUM)
                        .description("CSP에 'unsafe-inline' 또는 'unsafe-eval'이 포함되어 있습니다.")
                        .evidence("CSP=" + truncate(cspValue, 200))
                        .confidence(0.8)
                        .riskScore(SeverityWeights.toRisk(Severity.MEDIUM))
                        .requestLine(ProbeEngine.requestLine("GET", url))
                        .evidenceSnippet("")
                        .build());
            }
        }

        // HSTS(HTTPS일 때 권장)
        if ("https".equalsIgnoreCase(url.getScheme()) && !hasHsts) {
            out.add(missingHeader(url, "Strict-Transport-Security"));
        }

        // Referrer-Policy 미설정도 Low로 보고
        if (!hasRefp) {
            out.add(missingHeader(url, "Referrer-Policy"));
        }

        // 5) 쿠키 속성(HttpOnly/Secure) 점검 — 대소문자 무시로 모든 Set-Cookie 수집
        for (String setCookie : getAllHeaderValues(headers, "set-cookie")) {
            String lc = setCookie.toLowerCase(Locale.ROOT);
            if (!lc.contains("httponly")) {
                out.add(VulnResult.builder()
                        .url(url)
                        .issueType(IssueType.COOKIE_HTTPONLY_MISSING)
                        .severity(Severity.LOW)
                        .description("Set-Cookie에 HttpOnly 속성이 없습니다.")
                        .evidence(truncate(setCookie, 200))
                        .confidence(0.75)
                        .riskScore(SeverityWeights.toRisk(Severity.LOW))
                        .requestLine(ProbeEngine.requestLine("GET", url))
                        .evidenceSnippet("")
                        .build());
            }
            if ("https".equalsIgnoreCase(url.getScheme()) && !lc.contains("secure")) {
                out.add(VulnResult.builder()
                        .url(url)
                        .issueType(IssueType.COOKIE_SECURE_MISSING)
                        .severity(Severity.LOW)
                        .description("HTTPS인데 Set-Cookie에 Secure 속성이 없습니다.")
                        .evidence(truncate(setCookie, 200))
                        .confidence(0.75)
                        .riskScore(SeverityWeights.toRisk(Severity.LOW))
                        .requestLine(ProbeEngine.requestLine("GET", url))
                        .evidenceSnippet("")
                        .build());
            }
        }

        // 6) [Anomaly] Content-Type 불일치 (INFO)
        {
            String ct = firstHeaderValue(headers, "content-type");
            String b  = body.trim();
            if (ct != null) {
                String ctLc = ct.toLowerCase(Locale.ROOT);

                // JSON인데 HTML처럼 보임
                if (ctLc.contains("application/json")) {
                    boolean looksHtml = b.startsWith("<!doctype") || b.startsWith("<html") || b.contains("</html>");
                    if (looksHtml) {
                        out.add(VulnResult.builder()
                                .url(url)
                                .issueType(IssueType.ANOMALY_CONTENT_TYPE_MISMATCH)
                                .severity(Severity.INFO)
                                .description("Content-Type이 JSON이지만 응답은 HTML처럼 보입니다.")
                                .evidence("Content-Type=" + truncate(ct, 120))
                                .confidence(0.7)
                                .riskScore(SeverityWeights.toRisk(Severity.INFO))
                                .requestLine(ProbeEngine.requestLine("GET", url))
                                .evidenceSnippet(snippet(body, null))
                                .build());
                    }
                }

                // HTML인데 JSON처럼 보임
                if (ctLc.contains("text/html")) {
                    boolean looksJson = (b.startsWith("{") || b.startsWith("[")) && b.contains(":");
                    if (looksJson) {
                        out.add(VulnResult.builder()
                                .url(url)
                                .issueType(IssueType.ANOMALY_CONTENT_TYPE_MISMATCH)
                                .severity(Severity.INFO)
                                .description("Content-Type이 HTML이지만 응답은 JSON처럼 보입니다.")
                                .evidence("Content-Type=" + truncate(ct, 120))
                                .confidence(0.7)
                                .riskScore(SeverityWeights.toRisk(Severity.INFO))
                                .requestLine(ProbeEngine.requestLine("GET", url))
                                .evidenceSnippet(snippet(body, null))
                                .build());
                    }
                }
            }
        }

        // 7) [Anomaly] 스택트레이스/예외 토큰 (INFO)
        {
            Matcher m = P_STACKTRACE.matcher(body);
            if (m.find()) {
                String hit = m.group(1);
                out.add(VulnResult.builder()
                        .url(url)
                        .issueType(IssueType.ANOMALY_STACKTRACE_TOKEN)
                        .severity(Severity.INFO)
                        .description("응답 본문에 스택트레이스/예외 토큰이 노출되었습니다.")
                        .evidence(truncate(hit, 200))
                        .confidence(0.75)
                        .riskScore(SeverityWeights.toRisk(Severity.INFO))
                        .requestLine(ProbeEngine.requestLine("GET", url))
                        .evidenceSnippet(snippet(body, hit))
                        .build());
            }
        }

        // 8) [Anomaly] 응답 크기 변동(±25%) — 텍스트류 Content-Type만
        {
            String ct = firstHeaderValue(headers, "content-type");
            if (isTextLike(ct)) {
                int len = body.length();
                if (len >= SIZE_MIN_BASELINE) {
                    String key = normKey(url);
                    SizeStat stat = sizeStats.computeIfAbsent(key, k -> new SizeStat());
                    boolean alert = false;
                    double delta = 0.0;
                    long baseline;

                    synchronized (stat) {
                        if (stat.count >= 1) {
                            baseline = Math.max(SIZE_MIN_BASELINE, stat.avgLen);
                            delta = Math.abs(len - baseline) / (double) baseline;
                            alert = (delta >= SIZE_DELTA_THRESHOLD);
                        }
                        long newCount = stat.count + 1;
                        long newAvg = (stat.count == 0) ? len
                                : Math.round((stat.avgLen * (stat.count) + len) / (double) newCount);
                        stat.count = newCount;
                        stat.avgLen = newAvg;
                    }

                    if (alert) {
                        Severity sev = (delta >= 0.50) ? Severity.LOW : Severity.INFO;
                        String ev = String.format(Locale.ROOT, "len=%d, baseline≈%d, delta=%.0f%%",
                                len, Math.max(SIZE_MIN_BASELINE, sizeStats.get(key).avgLen), delta * 100.0);
                        out.add(VulnResult.builder()
                                .url(url)
                                .issueType(IssueType.ANOMALY_SIZE_DELTA)
                                .severity(sev)
                                .description("동일 경로 대비 응답 크기 변동이 큽니다(환경/AB테스트/에러/리다이렉트 등 확인 권장).")
                                .evidence(ev)
                                .confidence(0.55)
                                .riskScore(SeverityWeights.toRisk(sev))
                                .requestLine(ProbeEngine.requestLine("GET", url))
                                .evidenceSnippet(snippet(body, null))
                                .build());
                    }
                }
            }
        }

        return out;
    }

    // ----------------- helpers -----------------
    private static boolean hasHeader(Map<String, List<String>> headers, String key) {
        for (String k : headers.keySet()) {
            if (k != null && k.equalsIgnoreCase(key)) return true;
        }
        return false;
    }

    private static String firstHeaderValue(Map<String, List<String>> headers, String key) {
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(key) && !e.getValue().isEmpty()) {
                return e.getValue().get(0);
            }
        }
        return null;
    }

    /** 대소문자 무시로 특정 헤더의 모든 값을 수집(Set-Cookie 대응). */
    private static List<String> getAllHeaderValues(Map<String, List<String>> headers, String key) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(key) && e.getValue() != null) {
                out.addAll(e.getValue());
            }
        }
        return out;
    }

    private static VulnResult missingHeader(URI url, String headerName) {
        return VulnResult.builder()
                .url(url)
                .issueType(IssueType.MISSING_SECURITY_HEADER)
                .severity(Severity.LOW)
                .description(headerName + " 헤더가 설정되어 있지 않습니다.")
                .evidence("missing=" + headerName)
                .confidence(0.8)
                .riskScore(SeverityWeights.toRisk(Severity.LOW))
                .requestLine(ProbeEngine.requestLine("GET", url))
                .evidenceSnippet("")
                .build();
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    private static String snippet(String body, String token) {
        try {
            if (token == null || token.isBlank()) {
                return (body == null) ? "" : (body.length() <= 160 ? body : body.substring(0, 160) + "...");
            }
            return ProbeEngine.snippetAround(body, token, 80);
        } catch (Throwable ignore) {
            return "";
        }
    }

    private static boolean isTextLike(String contentType) {
        if (contentType == null) return true;
        String ct = contentType.toLowerCase(Locale.ROOT);
        return ct.contains("text/") || ct.contains("json") || ct.contains("xml")
                || ct.contains("javascript") || ct.contains("xhtml");
    }

    private static String normKey(URI url) {
        if (url == null) return "unknown";
        String host = url.getAuthority() == null ? "" : url.getAuthority().toLowerCase(Locale.ROOT);
        String path = url.getPath() == null ? "/" : url.getPath();
        return host + "|" + path;
    }
}
