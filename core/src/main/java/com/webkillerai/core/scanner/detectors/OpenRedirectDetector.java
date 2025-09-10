// core/src/main/java/com/webkillerai/core/scanner/detectors/OpenRedirectDetector.java
package com.webkillerai.core.scanner.detectors;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import com.webkillerai.core.util.UrlParamUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Open Redirect detector (no-redirect client; follow=false).
 * - Tries candidate param keys and two encodings per key (double-encoded & normal-encoded).
 * - First does GET (no-redirect). If no 3xx/Location, falls back to HEAD (no-redirect).
 * - Considers a finding only when Location points to an external host.
 */
public final class OpenRedirectDetector {

    private static final Logger LOG = LoggerFactory.getLogger(OpenRedirectDetector.class);

    // Common param key candidates (most-likely first)
    private static final List<String> KEYS = List.of(
            "next", "redirect", "url", "returnUrl", "return", "dest", "destination",
            "target", "continue", "r", "to"
    );

    /** External dummy destination used for probing */
    private static final String EXT = "https://wkai.example/";

    /** Minimal Accept to avoid weird 406s */
    private static final Map<String, String> ACCEPT_HTML = Map.of(
            "Accept", "text/html,application/xhtml+xml"
    );

    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base) {
        Objects.requireNonNull(engine, "engine");
        Objects.requireNonNull(base, "base");

        Mode mode = (cfg != null ? cfg.getMode() : Mode.SAFE_PLUS);
        if (mode == Mode.SAFE) return Optional.empty(); // defensive: SAFE에서는 액티브 안 함

        final String baseHost = normalizeHost(base.getHost());

        // Prefer keys already present in the query string; otherwise try a short default list.
        List<String> tryKeys = new ArrayList<>();
        String rawQ = base.getRawQuery();
        if (rawQ != null) {
            for (String k : KEYS) {
                if (rawQ.contains(k + "=")) tryKeys.add(k);
            }
        }
        if (tryKeys.isEmpty()) tryKeys = List.of("next", "redirect", "url");

        for (String key : tryKeys) {
            for (URI target : buildCandidates(base, key)) {
                try {
                    LOG.debug("[OR] probe {} -> {}", key, target);

                    // 1) GET (no redirect)
                    HttpResponse<String> rsp = engine.getNoRedirect(target, ACCEPT_HTML);
                    int code = rsp.statusCode();
                    String loc = header(rsp, "Location");

                    String methodUsed = "GET";

                    // 2) Fallback to HEAD (no redirect) if needed
                    if (!isRedirect(code, loc)) {
                        HttpResponse<String> head = engine.headNoRedirect(target, ACCEPT_HTML);
                        code = head.statusCode();
                        loc = header(head, "Location");
                        methodUsed = "HEAD";
                    }

                    if (isRedirect(code, loc)) {
                        if (isExternal(loc, baseHost)) {
                            String reqLine = ProbeEngine.requestLine(methodUsed, target);
                            String ev = "HTTP " + code + "\nLocation: " + loc;

                            VulnResult vr = VulnResult.builder()
                                    .url(target)
                                    .issueType(IssueType.OPEN_REDIRECT_PATTERN)
                                    .severity(Severity.MEDIUM)
                                    .description("Open redirect parameter '" + key + "' allows redirect to external domain.")
                                    .evidence(ev)
                                    .requestLine(reqLine)
                                    .evidenceSnippet(ev)
                                    .confidence(0.85)
                                    .build();
                            return Optional.of(vr);
                        }
                    }
                } catch (Exception e) {
                    // Network/timeout/IllArg — skip this candidate and continue
                    LOG.debug("[OR] error on {}: {}", target, e.toString());
                }
            }
        }
        return Optional.empty();
    }

    /** Build two candidate URLs per key: double-encoded & normally-encoded; plus UrlParamUtil variant. */
    private static List<URI> buildCandidates(URI base, String key) {
        List<URI> out = new ArrayList<>(3);

        // (A) Double-encoded style (common bypass)
        try {
            String enc = URLEncoder.encode(URLEncoder.encode(EXT, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
            String sep = (base.getRawQuery() == null || base.getRawQuery().isEmpty()) ? "?" : "&";
            out.add(URI.create(base.toString() + sep + key + "=" + enc));
        } catch (Exception ignore) {}

        // (B) Normal-encoded style
        try {
            String enc = URLEncoder.encode(EXT, StandardCharsets.UTF_8);
            String sep = (base.getRawQuery() == null || base.getRawQuery().isEmpty()) ? "?" : "&";
            out.add(URI.create(base.toString() + sep + key + "=" + enc));
        } catch (Exception ignore) {}

        // (C) UrlParamUtil helper (adds or appends param)
        try {
            Map<String, List<String>> add = Map.of(key, List.of(EXT));
            out.add(UrlParamUtil.withAddedParams(base, add));
        } catch (Exception ignore) {}

        // De-dup while preserving order
        LinkedHashSet<URI> dedup = new LinkedHashSet<>(out);
        return new ArrayList<>(dedup);
    }

    private static boolean isRedirect(int code, String loc) {
        return code >= 300 && code < 400 && loc != null && !loc.isBlank();
        // If some servers signal via Refresh only, we ignore (too noisy for SAFE_PLUS).
    }

    private static String header(HttpResponse<?> r, String name) {
        return r.headers().firstValue(name).orElse(null);
    }

    private static boolean isExternal(String loc, String baseHost) {
        try {
            URI u = URI.create(loc);
            // Absolute URI: https://host/...
            if (u.isAbsolute()) {
                String locHost = normalizeHost(u.getHost());
                return !locHost.isEmpty() && !locHost.equalsIgnoreCase(baseHost);
            }
            // Scheme-relative: //host/...
            if (loc.startsWith("//")) {
                URI u2 = URI.create("http:" + loc);
                String locHost = normalizeHost(u2.getHost());
                return !locHost.isEmpty() && !locHost.equalsIgnoreCase(baseHost);
            }
        } catch (Exception ignore) {
            // invalid Location — treat as not external
        }
        return false; // relative paths are considered internal
    }

    private static String normalizeHost(String h) {
        return (h == null) ? "" : h.toLowerCase(Locale.ROOT);
    }
}
