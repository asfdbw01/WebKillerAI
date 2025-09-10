package com.webkillerai.core.scanner.detectors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.webkillerai.core.model.Mode;            // ★ 변경: 최상위 Mode
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CorsMisconfigDetectorTest {

    static HttpServer s;
    static int port;

    @BeforeAll
    static void up() throws Exception {
        s = HttpServer.create(new InetSocketAddress(0), 0);
        port = s.getAddress().getPort();

        // 미스컨피그: ACAO='*' + ACAC=true
        s.createContext("/cors-bad", ex -> {
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                ex.getResponseHeaders().add("Access-Control-Allow-Credentials", "true");
                respond(ex, 204, "text/plain", "");
            } else {
                respond(ex, 200, "text/plain; charset=utf-8", "ok");
            }
        });

        // 정상: ACAO='*'지만 ACAC 미포함
        s.createContext("/cors-ok", ex -> {
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                respond(ex, 204, "text/plain", "");
            } else {
                respond(ex, 200, "text/plain; charset=utf-8", "ok");
            }
        });

        s.start();
    }

    @AfterAll
    static void down() { s.stop(0); }

    @Test
    void detect_misconfig_when_star_and_credentials_true() {
        // ★ 핵심: 최상위 Mode 사용 + var 체이닝 말고 명시적으로
        ScanConfig cfg = new ScanConfig();
        cfg.setMode(Mode.SAFE_PLUS);

        ProbeEngine engine = new ProbeEngine(cfg);
        CorsMisconfigDetector det = new CorsMisconfigDetector();

        Optional<VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:" + port + "/cors-bad"));

        assertTrue(vr.isPresent(), "should flag ACAO='*' with ACAC=true");
        assertNotNull(vr.get().getEvidenceSnippet());
        assertTrue(vr.get().getEvidenceSnippet().contains("Access-Control-Allow-Origin"));
    }

    @Test
    void ignore_when_credentials_not_true() {
        ScanConfig cfg = new ScanConfig();
        cfg.setMode(Mode.SAFE_PLUS);

        ProbeEngine engine = new ProbeEngine(cfg);
        CorsMisconfigDetector det = new CorsMisconfigDetector();

        Optional<VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:" + port + "/cors-ok"));

        assertTrue(vr.isEmpty(), "should not flag when ACAC is absent/false");
    }

    private static void respond(HttpExchange ex, int code, String ctype, String body) throws java.io.IOException {
        ex.getResponseHeaders().set("Content-Type", ctype);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
