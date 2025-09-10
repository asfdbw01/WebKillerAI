package com.webkillerai.core.scanner.detectors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.webkillerai.core.model.Mode;          // ★ 최상위 Mode
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class OpenRedirectDetectorTest {

    static HttpServer s;
    static int port;

    // 디텍터가 시도하는 대표 키들과 동일하게 서버도 허용하도록 구성
    private static final List<String> ALL_KEYS = List.of(
            "redirect","returnUrl","return","next","url","dest","destination","target","continue","r","to"
    );

    @BeforeAll
    static void up() throws Exception {
        s = HttpServer.create(new InetSocketAddress(0), 0);
        port = s.getAddress().getPort();

        // /redir : 쿼리에 ALL_KEYS 중 하나라도 있으면 302 Location=<그 값> (절대 URL이면 외부로, 상대면 내부로 취급)
        s.createContext("/redir", ex -> {
            Map<String, String> qs = parseQuery(ex.getRequestURI().getRawQuery());
            String loc = null;
            for (String k : ALL_KEYS) {
                if (qs.containsKey(k)) {
                    loc = qs.get(k);
                    break;
                }
            }
            if (loc != null) {
                ex.getResponseHeaders().add("Location", URLDecoder.decode(loc, StandardCharsets.UTF_8));
                ex.sendResponseHeaders(302, -1);
            } else {
                respond(ex, 200, "text/plain; charset=utf-8", "ok");
            }
        });

        // /safe : redirect=/internal 이면 302 Location=/internal (같은 호스트 상대경로)
        s.createContext("/safe", ex -> {
            Map<String, String> qs = parseQuery(ex.getRequestURI().getRawQuery());
            String v = qs.get("redirect");
            if ("/internal".equals(v)) {
                ex.getResponseHeaders().add("Location", "/internal");
                ex.sendResponseHeaders(302, -1);
            } else {
                respond(ex, 200, "text/plain; charset=utf-8", "ok");
            }
        });

        s.start();
    }

    @AfterAll
    static void down() {
        if (s != null) s.stop(0);
    }

    @Test
    void detects_external_redirect() {
        // SAFE_PLUS 혹은 AGGRESSIVE_LITE에서 동작하도록 디텍터 구현됨
        var cfg = new ScanConfig().setMode(Mode.SAFE_PLUS);
        var engine = new ProbeEngine(cfg);
        var det = new OpenRedirectDetector();

        // base URL에는 쿼리 없음 → 디텍터가 내부적으로 ["redirect","next","url"] 순으로 시도
        Optional<com.webkillerai.core.model.VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:" + port + "/redir"));

        assertTrue(vr.isPresent(), "should flag external redirect");
        assertNotNull(vr.get().getEvidenceSnippet());
        assertTrue(vr.get().getEvidenceSnippet().toLowerCase(Locale.ROOT).contains("location"),
                "evidence should include Location header");
    }

    @Test
    void ignores_relative_or_same_host_redirect() {
        var cfg = new ScanConfig().setMode(Mode.SAFE_PLUS);
        var engine = new ProbeEngine(cfg);
        var det = new OpenRedirectDetector();

        // 서버가 상대경로로만 리다이렉트하도록 구성된 엔드포인트
        Optional<com.webkillerai.core.model.VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:" + port + "/safe?redirect=/internal"));

        assertTrue(vr.isEmpty(), "should not flag relative/same-host redirect");
    }

    // ---------------- helpers ----------------

    private static Map<String, String> parseQuery(String raw) {
        if (raw == null || raw.isBlank()) return Collections.emptyMap();
        return Arrays.stream(raw.split("&"))
                .map(p -> {
                    int i = p.indexOf('=');
                    String k = i >= 0 ? p.substring(0, i) : p;
                    String v = i >= 0 ? p.substring(i + 1) : "";
                    return Map.entry(k, v);
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (a,b)->a, LinkedHashMap::new));
    }

    private static void respond(HttpExchange ex, int code, String ctype, String body) throws java.io.IOException {
        ex.getResponseHeaders().set("Content-Type", ctype);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
