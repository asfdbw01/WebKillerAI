// core/src/main/java/com/webkillerai/core/scanner/probe/ProbeEngine.java
package com.webkillerai.core.scanner.probe;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.ActiveScanRunner;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.HashSet;                    // ← added
import java.util.Set;                        // ← added

/**
 * Read-only ProbeEngine:
 * - GET/HEAD/OPTIONS 전송 헬퍼
 * - 리다이렉트 추적용/비추적용 HttpClient를 분리 (getNoRedirect 등은 절대 따라가지 않음)
 * - Evidence 유틸(requestLine/snippetAround/maskSensitive)
 */
public final class ProbeEngine {

    private final HttpClient client;            // cfg에 따라 follow 여부 결정
    private final HttpClient clientNoRedirect;  // 항상 Redirect.NEVER
    private final Duration timeout;

    public ProbeEngine(ScanConfig cfg) {
        Objects.requireNonNull(cfg, "cfg");
        this.timeout = Duration.ofMillis(Math.max(1, cfg.getTimeoutMs()));

        this.client = HttpClient.newBuilder()
                .followRedirects(cfg.isFollowRedirects()
                        ? HttpClient.Redirect.NORMAL
                        : HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();

        this.clientNoRedirect = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    // ============ 기본(설정 준수) 전송 ============
    public HttpResponse<String> get(URI url, Map<String, String> headers) throws Exception {
        return send(client, "GET", url, safe(headers));
    }

    public HttpResponse<String> head(URI url, Map<String, String> headers) throws Exception {
        return send(client, "HEAD", url, safe(headers));
    }

    public HttpResponse<String> options(URI url, Map<String, String> headers) throws Exception {
        return send(client, "OPTIONS", url, safe(headers));
    }

    // ============ 리다이렉트 비추적 전송 ============
    public HttpResponse<String> getNoRedirect(URI url, Map<String, String> headers) throws Exception {
        return send(clientNoRedirect, "GET", url, safe(headers));
    }

    public HttpResponse<String> headNoRedirect(URI url, Map<String, String> headers) throws Exception {
        return send(clientNoRedirect, "HEAD", url, safe(headers));
    }

    public HttpResponse<String> optionsNoRedirect(URI url, Map<String, String> headers) throws Exception {
        return send(clientNoRedirect, "OPTIONS", url, safe(headers));
    }

    // ============ CORS 프리플라이트 ============
    public HttpResponse<String> preflight(URI url, String origin, String method) throws Exception {
        var h = new java.util.LinkedHashMap<String,String>();
        if (origin != null && !origin.isBlank()) h.put("Origin", origin);
        if (method != null && !method.isBlank()) h.put("Access-Control-Request-Method", method);
        h.putIfAbsent("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        return options(url, h);
    }

    // ============ 내부 공통 ============
    private static Map<String, String> safe(Map<String, String> h) {
        return (h == null) ? Collections.emptyMap() : h;
    }

    private HttpResponse<String> send(HttpClient hc, String method, URI url, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(url)
                .timeout(timeout)
                .method(method, HttpRequest.BodyPublishers.noBody());

        // 합리적 기본 Accept (케이스 무시)
        boolean hasAccept = headers != null && headers.keySet().stream().anyMatch(k -> k.equalsIgnoreCase("Accept"));
        if (!hasAccept) {
            b.header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        }
        if (headers != null) headers.forEach(b::header);

        return hc.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    // ============ Evidence helpers ============
    /** "GET https://example.com/a?b=1 HTTP/1.1" */
    public static String requestLine(String method, URI url) {
        String m = (method == null || method.isEmpty()) ? "GET" : method;
        return m + " " + url + " HTTP/1.1";
    }

    /** 본문에서 token 주변 ±radius 추출(없으면 앞부분). radius <= 0이면 80. */
    public static String snippetAround(String body, String token, int radius) {
        if (body == null || body.isEmpty()) return "";
        int r = (radius <= 0) ? 80 : radius;

        if (token == null || token.isEmpty()) {
            int end = Math.min(body.length(), r * 2);
            return body.substring(0, end);
        }

        int i = body.indexOf(token);
        if (i < 0) {
            int end = Math.min(body.length(), r * 2);
            return body.substring(0, end);
        }

        int s = Math.max(0, i - r);
        int e = Math.min(body.length(), i + token.length() + r);
        return body.substring(s, e);
    }

    // ============ Sanitizer ============
    private static final Pattern PASSWD_LINE =
            Pattern.compile("(?m)^root:x:[^\\n\\r]*$");
    private static final Pattern KEY_VALUE =
            Pattern.compile("(?i)(\\b(?:api[_-]?key|secret|token)\\b\\s*[:=]\\s*)([^\\s\"'\\\\]+)");

    /** 민감 토큰 가벼운 마스킹 */
    public static String maskSensitive(String s) {
        if (s == null || s.isEmpty()) return s;
        String out = PASSWD_LINE.matcher(s).replaceAll("root:x:***");
        out = KEY_VALUE.matcher(out).replaceAll("$1***");
        return out;
    }

    // ============ ActiveScanRunner 브리지(실구현) ============
    /**
     * ActiveScanRunner에서 전달한 프로브 계획을 받아 실행한다.
     * - PARAM  : 쿼리 변조 GET(no-redirect는 OR 판정용), 본문/헤더 판정
     * - HEADER : 헤더 주입 GET (+옵션 프리플라이트)
     * - PAGE   : 페이지 단위 검사(Mixed)
     *
     * 중복 억제:
     * - HEADER 계열(현재 CORS)은 URL당 동일 IssueType 1건만 리포트.
     */
    public List<VulnResult> executePlanned(ScanConfig cfg, URI url, List<ActiveScanRunner.ProbePlan> plans) {
        if (plans == null || plans.isEmpty()) return List.of();
        List<VulnResult> out = new ArrayList<>();

        // HEADER 결과 중복 억제(이슈타입 단위)
        Set<IssueType> headerTypesReported = new HashSet<>();

        for (ActiveScanRunner.ProbePlan p : plans) {
            try {
                List<VulnResult> r = switch (p.kind) {
                    case PARAM -> execParam(url, p);
                    case HEADER -> execHeader(url, p);
                    case PAGE  -> execPage(url, p);
                };

                if (p.kind == ActiveScanRunner.ProbePlan.Kind.HEADER) {
                    // 현재는 CORS만 해당. 같은 IssueType은 한 번만 채택.
                    for (VulnResult vr : r) {
                        IssueType it = vr.getIssueType();
                        if (headerTypesReported.add(it)) {
                            out.add(vr);
                        }
                    }
                } else {
                    out.addAll(r);
                }
            } catch (Throwable ignore) {
                // plan 단위 실패는 무시
            }
        }
        return out;
    }

    // ----- PARAM probes ------------------------------------------------------

    private List<VulnResult> execParam(URI baseUrl, ActiveScanRunner.ProbePlan p) throws Exception {
        List<VulnResult> out = new ArrayList<>();
        String key = "-".equals(p.paramKey) ? "q" : p.paramKey; // 기본 키 보정
        URI u = withParam(baseUrl, key, p.payload);

        if ("OPEN_REDIRECT".equals(p.issueKey)) {
            HttpResponse<String> r = getNoRedirect(u, Map.of());
            int sc = r.statusCode();
            var locOpt = r.headers().firstValue("Location");
            if (sc / 100 == 3 && locOpt.isPresent()) {
                try {
                    URI locUri = URI.create(locOpt.get().trim());
                    String origHost = (baseUrl.getHost() == null ? "" : baseUrl.getHost().toLowerCase());
                    String newHost  = (locUri.getHost() == null ? "" : locUri.getHost().toLowerCase());
                    if (!newHost.isEmpty() && !origHost.equals(newHost)) {
                        String req = requestLine("GET", u);
                        String evs = "Location: " + locUri;
                        out.add(VulnResult.builder()
                                .url(u)
                                .issueType(IssueType.OPEN_REDIRECT_PATTERN)
                                .severity(Severity.MEDIUM)
                                .description("Open Redirect to external host")
                                .evidence(evs)
                                .requestLine(req)
                                .evidenceSnippet(evs)
                                .confidence(0.8)
                                .build());
                    }
                } catch (IllegalArgumentException ignore) {}
            }
            return out;
        }

        HttpResponse<String> r = get(u, Map.of());
        String body = (r.body() == null ? "" : r.body());

        if ("XSS_REFLECTED".equals(p.issueKey)) {
            if (body.contains("WKAI") && body.toLowerCase().contains("<svg")) {
                String req = requestLine("GET", u);
                String snip = maskSensitive(snippetAround(body, "WKAI", 80));
                out.add(VulnResult.builder()
                        .url(u)
                        .issueType(IssueType.XSS_REFLECTED)
                        .severity(Severity.HIGH)
                        .description("Reflected XSS: payload echoed without escaping")
                        .evidence("payload=" + p.payloadSig)
                        .requestLine(req)
                        .evidenceSnippet(snip)
                        .confidence(0.9)
                        .build());
            }
            return out;
        }

        if ("SQLI_ERROR".equals(p.issueKey)) {
            String match = findSqlError(body);
            if (match != null) {
                String req = requestLine("GET", u);
                String snip = maskSensitive(snippetAround(body, match, 80));
                out.add(VulnResult.builder()
                        .url(u)
                        .issueType(IssueType.SQLI_PATTERN)
                        .severity(Severity.HIGH)
                        .description("SQL error signature observed")
                        .evidence(match)
                        .requestLine(req)
                        .evidenceSnippet(snip)
                        .confidence(0.85)
                        .build());
            }
            return out;
        }

        if ("PATH_TRAVERSAL".equals(p.issueKey)) {
            String match = findLfiSignature(body);
            if (match != null) {
                String req = requestLine("GET", u);
                String snip = maskSensitive(snippetAround(body, match, 80));
                out.add(VulnResult.builder()
                        .url(u)
                        .issueType(IssueType.PATH_TRAVERSAL)
                        .severity(Severity.HIGH)
                        .description("Potential Local File Inclusion / Path Traversal")
                        .evidence(match)
                        .requestLine(req)
                        .evidenceSnippet(snip)
                        .confidence(0.8)
                        .build());
            }
            return out;
        }

        if ("SSTI_PATTERN".equals(p.issueKey) || "SSTI".equals(p.issueKey)) {
            String match = findSstiSignal(body);
            if (match != null) {
                String req = requestLine("GET", u);
                String snip = maskSensitive(snippetAround(body, match, 80));
                out.add(VulnResult.builder()
                        .url(u)
                        .issueType(IssueType.SSTI)
                        .severity(Severity.HIGH)
                        .description("Server-Side Template Injection indicator")
                        .evidence(match)
                        .requestLine(req)
                        .evidenceSnippet(snip)
                        .confidence(0.8)
                        .build());
            }
            return out;
        }

        return out;
    }

    // ----- HEADER probes (CORS) ---------------------------------------------

    private List<VulnResult> execHeader(URI url, ActiveScanRunner.ProbePlan p) throws Exception {
        Map<String,String> headers = new java.util.LinkedHashMap<>();
        // p.payload 예: "Origin:https://evil.example"
        String[] hv = p.payload.split(":", 2);
        if (hv.length == 2) {
            headers.put(hv[0].trim(), hv[1].trim());
        }

        HttpResponse<String> r = get(url, headers);
        String acao = r.headers().firstValue("Access-Control-Allow-Origin").orElse(null);
        String acac = r.headers().firstValue("Access-Control-Allow-Credentials").orElse(null);

        boolean credTrue = acac != null && acac.trim().equalsIgnoreCase("true");
        String origin = headers.getOrDefault("Origin", "");

        boolean misconfig = false;
        String evidence = null;

        if (credTrue && acao != null) {
            if ("*".equals(acao.trim())) {
                misconfig = true;
                evidence = "ACAO:* with ACAC:true";
            } else if (!origin.isBlank() && acao.trim().equalsIgnoreCase(origin.trim())) {
                misconfig = true;
                evidence = "ACAO:Origin-reflection with ACAC:true";
            } else if ("null".equalsIgnoreCase(acao.trim())) {
                misconfig = true;
                evidence = "ACAO:null with ACAC:true";
            }
        }

        if (misconfig) {
            String req = requestLine("GET", url);
            String hdrBlock = "Access-Control-Allow-Origin: " + (acao == null ? "-" : acao)
                    + "\nAccess-Control-Allow-Credentials: " + (acac == null ? "-" : acac);
            String snip = maskSensitive(hdrBlock);
            return List.of(VulnResult.builder()
                    .url(url)
                    .issueType(IssueType.CORS_MISCONFIG)
                    .severity(Severity.MEDIUM)
                    .description("CORS misconfiguration (credentials with wildcard/reflection)")
                    .evidence(evidence)
                    .requestLine(req)
                    .evidenceSnippet(snip)
                    .confidence(0.8)
                    .build());
        }
        return List.of();
    }

    // ----- PAGE probes (Mixed Content) --------------------------------------

    private List<VulnResult> execPage(URI url, ActiveScanRunner.ProbePlan p) throws Exception {
        if (!"https".equalsIgnoreCase(url.getScheme())) return List.of();

        HttpResponse<String> r = get(url, Map.of());
        String body = (r.body() == null ? "" : r.body());

        int idx = indexOfHttpResource(body);
        if (idx >= 0) {
            String token = "http://";
            String req = requestLine("GET", url);
            String snip = maskSensitive(snippetAround(body, token, 80));
            return List.of(VulnResult.builder()
                    .url(url)
                    .issueType(IssueType.MIXED_CONTENT)
                    .severity(Severity.LOW)
                    .description("HTTP resource referenced in HTTPS page")
                    .evidence(token)
                    .requestLine(req)
                    .evidenceSnippet(snip)
                    .confidence(0.75)
                    .build());
        }
        return List.of();
    }

    // ===== Helpers for detections ===========================================

    private static int indexOfHttpResource(String body) {
        if (body == null) return -1;
        int i = body.indexOf("http://");
        if (i >= 0) return i;
        Pattern attr = Pattern.compile("(?i)(src|href|data|action)\\s*=\\s*\"http://[^\"]+\"");
        var m = attr.matcher(body);
        if (m.find()) return m.start();
        return -1;
    }

    private static String findSqlError(String body) {
        if (body == null) return null;
        String[] sigs = {
                "you have an error in your sql syntax",
                "unclosed quotation mark after the character string",
                "sqlstate",
                "syntax error near",
                "warning: mysql",
                "ORA-0",
                "SQLiteException",
                "PG::SyntaxError",
                "mysql_fetch_",
                "System.Data.SqlClient",
                "org.hibernate.exception",
                "MySqlException"
        };
        String lower = body.toLowerCase();
        for (String s : sigs) if (lower.contains(s)) return s;
        return null;
    }

    private static String findLfiSignature(String body) {
        if (body == null) return null;
        if (body.contains("root:x:")) return "root:x:";
        if (body.contains("[fonts]")) return "[fonts]"; // win.ini 힌트
        return null;
    }

    private static String findSstiSignal(String body) {
        if (body == null) return null;
        if (body.contains("49WKAI")) return "49WKAI";
        String[] errs = {
                "TemplateSyntaxError", "Jinja2", "Thymeleaf", "Freemarker",
                "VelocityException", "MustacheException", "PebbleException"
        };
        for (String e : errs) if (body.contains(e)) return e;
        return null;
    }

    private static URI withParam(URI url, String key, String value) {
        try {
            String q = url.getRawQuery();
            String encKey = URLEncoder.encode(key, StandardCharsets.UTF_8);
            String encVal = URLEncoder.encode(value, StandardCharsets.UTF_8);

            String newQuery;
            if (q == null || q.isBlank()) {
                newQuery = encKey + "=" + encVal;
            } else {
                String[] parts = q.split("&");
                boolean replaced = false;
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < parts.length; i++) {
                    String part = parts[i];
                    if (part.isEmpty()) continue;
                    int eq = part.indexOf('=');
                    String k = (eq >= 0 ? part.substring(0, eq) : part);
                    if (!replaced && k.equals(encKey)) {
                        sb.append(encKey).append('=').append(encVal);
                        replaced = true;
                    } else {
                        sb.append(part);
                    }
                    if (i < parts.length - 1) sb.append('&');
                }
                if (!replaced) {
                    if (sb.length() > 0 && sb.charAt(sb.length()-1) != '&') sb.append('&');
                    sb.append(encKey).append('=').append(encVal);
                }
                newQuery = sb.toString();
            }

            return new URI(url.getScheme(), url.getUserInfo(), url.getHost(), url.getPort(),
                    url.getPath(), newQuery, url.getFragment());
        } catch (Exception e) {
            return url; // 실패 시 원본 유지
        }
    }
}
