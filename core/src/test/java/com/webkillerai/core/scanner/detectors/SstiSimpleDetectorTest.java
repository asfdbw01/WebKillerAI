package com.webkillerai.core.scanner.detectors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SstiSimpleDetectorTest {

    static HttpServer s;
    static int port;

    @BeforeAll
    static void up() throws Exception {
        s = HttpServer.create(new InetSocketAddress(0), 0);
        port = s.getAddress().getPort();

        // 평가되는 것처럼 응답(데모)
        s.createContext("/ssti-eval", ex -> {
            String q = ex.getRequestURI().getRawQuery();
            boolean hit = q != null && (
                    q.contains("%7B%7B7*7%7D%7DWKAI") || q.contains("{{7*7}}WKAI") ||
                    q.contains("%24%7B7*7%7DWKAI")   || q.contains("${7*7}WKAI")
            );
            String body = hit ? "hello 49WKAI world" : "ok";
            respond(ex, 200, "text/html; charset=utf-8", body);
        });

        // 템플릿 에러 노출처럼 응답(데모)
        s.createContext("/ssti-error", ex -> {
            String q = ex.getRequestURI().getRawQuery();
            boolean injected = q != null && (q.contains("%7B%7B") || q.contains("{{") || q.contains("${"));
            String body = injected
                    ? "<pre>jinja2.exceptions.TemplateSyntaxError: unexpected '}' at 1:3</pre>"
                    : "ok";
            respond(ex, 200, "text/html; charset=utf-8", body);
        });

        s.start();
    }

    @AfterAll
    static void down(){ s.stop(0); }

    @Test
    void detects_evaluated_expression() {
        var cfg = new ScanConfig().setMode(Mode.SAFE_PLUS);
        var engine = new ProbeEngine(cfg);
        var det = new SstiSimpleDetector();

        Optional<com.webkillerai.core.model.VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:"+port+"/ssti-eval"), "q");

        assertTrue(vr.isPresent(), "should detect evaluated SSTI");
        assertTrue(vr.get().getEvidenceSnippet().contains("49WKAI"));
    }

    @Test
    void detects_template_error_leak() {
        var cfg = new ScanConfig().setMode(Mode.SAFE_PLUS);
        var engine = new ProbeEngine(cfg);
        var det = new SstiSimpleDetector();

        Optional<com.webkillerai.core.model.VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:"+port+"/ssti-error"), "q");

        assertTrue(vr.isPresent(), "should detect template error leak");
        assertTrue(vr.get().getEvidenceSnippet().toLowerCase().contains("templatesyntaxerror"));
    }

    private static void respond(HttpExchange ex, int code, String ctype, String body) throws java.io.IOException {
        ex.getResponseHeaders().set("Content-Type", ctype);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
