package com.webkillerai.core.scanner.anomaly;

import com.webkillerai.core.model.HttpResponseData;
import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/** 패시브 이상탐지: 응답 길이 델타, Content-Type 불일치, 스택트레이스 토큰 */
public final class AnomalyEngine {

    // === 사이즈 델타 설정 ===
    private static final int SIZE_DELTA_PCT = 25; // ±25%
    private static final int LRU_CAP = 256;

    // path → 최근 크기(간단 EWMA)
    private final Map<String, Integer> sizeBaseline = new LinkedHashMap<>(16, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Integer> e) { return size() > LRU_CAP; }
    };

    // === Stacktrace / Error 토큰(보수적) ===
    private static final Pattern STACKTRACE = Pattern.compile(
            "(?is)(Traceback\\s*\\(most recent call last\\)|" +      // Python
            "Exception\\b|NullPointerException\\b|IndexOutOfBoundsException\\b|" + // Java
            "at\\s+[a-zA-Z0-9_$.]+\\([a-zA-Z0-9_$.]+:\\d+\\)|" +     // Java stack line
            "TypeError\\b|ReferenceError\\b|SyntaxError\\b|" +        // JS/Node
            "System\\.[A-Za-z0-9_.]+Exception\\b|" +                  // .NET
            "org\\.springframework\\.|org\\.hibernate\\.|javax\\.servlet\\.)"
    );

    public List<VulnResult> detect(HttpResponseData resp) {
        List<VulnResult> out = new ArrayList<>();
        final URI uri = resp.getUri();
        final String body = resp.getBody() == null ? "" : resp.getBody();
        final String req = ProbeEngine.requestLine("GET", uri);

        // 1) 응답 길이 델타
        String key = keyFor(uri);
        int len = body.length();
        Integer base = sizeBaseline.get(key);
        if (base != null && base > 0) {
            int diff = Math.abs(len - base);
            int pct = (int) Math.round((diff * 100.0) / Math.max(1, base));
            if (pct >= SIZE_DELTA_PCT) {
                String snippet = "prev≈" + base + "B → now=" + len + "B (Δ≈" + pct + "%)";
                out.add(VulnResult.builder()
                        .url(uri)
                        .issueType(IssueType.ANOMALY_SIZE_DELTA)
                        .severity(Severity.INFO)
                        .description("응답 크기 변동이 큼 (±" + SIZE_DELTA_PCT + "% 이상).")
                        .requestLine(req)
                        .evidenceSnippet(snippet)
                        .evidence(req + "\n" + snippet)
                        .confidence(0.6)
                        .build());
            }
            // EWMA 업데이트(보수적)
            int ewma = (int) Math.round(0.7 * base + 0.3 * len);
            sizeBaseline.put(key, ewma);
        } else {
            sizeBaseline.put(key, len);
        }

        // 2) Content-Type 불일치
        String ct = firstHeader(resp, "Content-Type");
        if (ct == null) ct = "";
        String trimmed = leadingNonWs(body, 64).toLowerCase(Locale.ROOT);
        boolean looksHtml = trimmed.contains("<html") || trimmed.startsWith("<!doctype");
        boolean looksJson = trimmed.startsWith("{") || trimmed.startsWith("[");
        boolean looksXml  = trimmed.startsWith("<?xml") || trimmed.startsWith("<rss") || trimmed.startsWith("<feed");

        String ctLc = ct.toLowerCase(Locale.ROOT);
        boolean isHtmlCT = ctLc.contains("text/html") || ctLc.contains("application/xhtml");
        boolean isJsonCT = ctLc.contains("application/json");
        boolean isXmlCT  = ctLc.contains("application/xml") || ctLc.contains("text/xml");

        boolean mismatch =
                (isHtmlCT && (looksJson || looksXml)) ||
                (isJsonCT && (looksHtml || looksXml)) ||
                (isXmlCT  && (looksHtml || looksJson)) ||
                (ctLc.isBlank() && (looksJson || looksXml)); // 명시 CT 없음 + 본문이 구조화 포맷

        if (mismatch) {
            String hit = looksJson ? "JSON-like body" : (looksXml ? "XML-like body" : "HTML-like body");
            String ev = "Content-Type: " + (ct.isBlank() ? "<missing>" : ct) + "\nBody looks like: " + hit;
            out.add(VulnResult.builder()
                    .url(uri)
                    .issueType(IssueType.ANOMALY_CONTENT_TYPE_MISMATCH)
                    .severity(Severity.INFO)
                    .description("Content-Type과 본문 포맷이 불일치할 수 있습니다.")
                    .requestLine(req)
                    .evidenceSnippet(ev)
                    .evidence(req + "\n" + ev)
                    .confidence(0.65)
                    .build());
        }

        // 3) 스택트레이스/에러 토큰
        var m = STACKTRACE.matcher(body);
        if (m.find()) {
            String token = m.group();
            String snippet = ProbeEngine.snippetAround(body, token.substring(0, Math.min(32, token.length())), 80);
            out.add(VulnResult.builder()
                    .url(uri)
                    .issueType(IssueType.ANOMALY_STACKTRACE_TOKEN)
                    .severity(Severity.INFO)
                    .description("서버 스택트레이스/에러 토큰이 응답에 포함되어 있습니다.")
                    .requestLine(req)
                    .evidenceSnippet(snippet)
                    .evidence(req + "\n" + snippet)
                    .confidence(0.7)
                    .build());
        }

        return out;
    }

    /* ------------ helpers ------------ */
    private static String keyFor(URI u) {
        String p = u.getPath();
        return (p == null || p.isBlank()) ? "/" : p;
    }

    private static String firstHeader(HttpResponseData r, String name) {
        List<String> v = r.getHeaders().get(name);
        if (v != null && !v.isEmpty()) return v.get(0);
        // case-insensitive fallback
        for (Map.Entry<String, List<String>> e : r.getHeaders().entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                return e.getValue().get(0);
            }
        }
        return null;
    }

    private static String leadingNonWs(String s, int max) {
        if (s == null) return "";
        int i = 0, n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) i++;
        int end = Math.min(n, i + Math.max(1, max));
        return s.substring(i, end);
    }
}
