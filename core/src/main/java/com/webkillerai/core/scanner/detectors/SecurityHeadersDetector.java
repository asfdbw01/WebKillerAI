package com.webkillerai.core.scanner.detectors;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import com.webkillerai.core.model.HttpResponseData;
import java.net.URI;
import java.util.*;

/** 패시브: 응답 헤더/쿠키 품질 점검 + Evidence 표준화(요청 라인 + 요약) */
public final class SecurityHeadersDetector {

    /** SignatureScanner에서 resp를 넘겨 호출 */
    public List<VulnResult> detect(HttpResponseData resp) {
        List<VulnResult> out = new ArrayList<>();
        URI url = resp.getUri();

        // --- 헤더 값 가져오기(프로젝트에 맞춰 아래 2개 메서드만 필요시 이름 조정) ---
        String hsts = header(resp, "Strict-Transport-Security");
        String csp  = header(resp, "Content-Security-Policy");
        String xfo  = header(resp, "X-Frame-Options");
        String xcto = header(resp, "X-Content-Type-Options");
        String refp = header(resp, "Referrer-Policy");
        String perms= header(resp, "Permissions-Policy");
        List<String> setCookies = headers(resp, "Set-Cookie");

        String req = ProbeEngine.requestLine("GET", url);

        // 1) HSTS (HTTPS일 때 없으면 MEDIUM, HTTP면 INFO)
        if (!isBlank(hsts)) {
            // ok
        } else {
            Severity sev = "https".equalsIgnoreCase(url.getScheme()) ? Severity.MEDIUM : Severity.INFO;
            String summary = "Strict-Transport-Security: (absent)";
            out.add(build(IssueType.MISSING_SECURITY_HEADER, sev, url,
                    "Security header missing: HSTS.", req, summary));
        }

        // 2) CSP (부재 → MEDIUM, 있더라도 너무 약하면 WEAK_CSP)
        if (isBlank(csp)) {
            String summary = "Content-Security-Policy: (absent)";
            out.add(build(IssueType.MISSING_SECURITY_HEADER, Severity.MEDIUM, url,
                    "Security header missing: CSP.", req, summary));
        } else if (isWeakCsp(csp)) {
            String summary = "Content-Security-Policy: " + elide(csp, 180);
            out.add(build(IssueType.WEAK_CSP, Severity.MEDIUM, url,
                    "Content-Security-Policy is weak/permissive.", req, summary));
        }

        // 3) X-Frame-Options 부재
        if (isBlank(xfo)) {
            String summary = "X-Frame-Options: (absent)";
            out.add(build(IssueType.MISSING_SECURITY_HEADER, Severity.LOW, url,
                    "Security header missing: X-Frame-Options.", req, summary));
        }

        // 4) X-Content-Type-Options 부재
        if (isBlank(xcto)) {
            String summary = "X-Content-Type-Options: (absent)";
            out.add(build(IssueType.MISSING_SECURITY_HEADER, Severity.LOW, url,
                    "Security header missing: X-Content-Type-Options.", req, summary));
        }

        // 5) Referrer-Policy 부재
        if (isBlank(refp)) {
            String summary = "Referrer-Policy: (absent)";
            out.add(build(IssueType.MISSING_SECURITY_HEADER, Severity.INFO, url,
                    "Security header missing: Referrer-Policy.", req, summary));
        }

        // 6) Permissions-Policy 부재(정보 수준)
        if (isBlank(perms)) {
            String summary = "Permissions-Policy: (absent)";
            out.add(build(IssueType.MISSING_SECURITY_HEADER, Severity.INFO, url,
                    "Security header missing: Permissions-Policy.", req, summary));
        }

        // 7) 쿠키 플래그 (Secure/HttpOnly)
        if (!setCookies.isEmpty()) {
            for (String sc : setCookies) {
                String name = cookieName(sc);
                String lowName = sc.toLowerCase(Locale.ROOT);
                if (!lowName.contains("httponly")) {
                    String summary = "Set-Cookie: " + elide(sc, 180);
                    out.add(build(IssueType.COOKIE_HTTPONLY_MISSING, Severity.LOW, url,
                            "Cookie without HttpOnly: " + name, req, summary));
                }
                if ("https".equalsIgnoreCase(url.getScheme()) && !lowName.contains("secure")) {
                    String summary = "Set-Cookie: " + elide(sc, 180);
                    out.add(build(IssueType.COOKIE_SECURE_MISSING, Severity.LOW, url,
                            "Cookie without Secure on HTTPS: " + name, req, summary));
                }
            }
        }

        return out;
    }

    /* ----------------- 헬퍼 ----------------- */

    private static VulnResult build(IssueType t, Severity sev, URI url,
                                    String desc, String req, String summary) {
        String evidence = req + "\n" + summary;
        return VulnResult.builder()
                .issueType(t)
                .severity(sev)
                .url(url)
                .description(desc)
                .requestLine(req)
                .evidenceSnippet(summary)
                .evidence(evidence)
                .build();
    }

    private static boolean isWeakCsp(String csp) {
        String lc = csp.toLowerCase(Locale.ROOT);
        // 완전 개방/거의 개방 패턴 몇 가지
        if (lc.contains("default-src *") || lc.contains("default-src 'unsafe-inline'") || lc.contains("default-src data: blob:")) return true;
        if (lc.contains("script-src *") || lc.contains("script-src 'unsafe-inline'") || lc.contains("script-src data: blob:")) return true;
        // 필요시 확장: 'unsafe-eval', frame-ancestors *, etc.
        return false;
    }

    private static String cookieName(String setCookie) {
        int i = setCookie.indexOf('=');
        if (i <= 0) return setCookie.split(";", 2)[0].trim();
        return setCookie.substring(0, i).trim();
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }
    private static String elide(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    // === 아래 2개는 프로젝트 HttpResponseData에 맞춰 필요시 메서드명만 조정 ===
    private static String header(HttpResponseData r, String name) {
        // r.header(name) 또는 r.getHeaders().get(name) 등 프로젝트 형태에 맞게 구현
        String v = null;
        try { v = r.header(name); } catch (Throwable ignore) {}
        if (v != null) return v;
        try {
            Map<String, List<String>> m = r.getHeaders();
            if (m != null) {
                for (var e : m.entrySet()) {
                    if (e.getKey() != null && e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                        return e.getValue().get(0);
                    }
                }
            }
        } catch (Throwable ignore) {}
        return null;
    }
    private static List<String> headers(HttpResponseData r, String name) {
        try {
            List<String> v = r.headers(name);
            if (v != null) return v;
        } catch (Throwable ignore) {}
        try {
            Map<String, List<String>> m = r.getHeaders();
            if (m != null) {
                for (var e : m.entrySet()) {
                    if (e.getKey() != null && e.getKey().equalsIgnoreCase(name) && e.getValue() != null) {
                        return e.getValue();
                    }
                }
            }
        } catch (Throwable ignore) {}
        return Collections.emptyList();
    }
}
