package com.webkillerai.core.scanner.detectors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.webkillerai.core.model.Mode;          // ★ 추가: 최상위 Mode
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class PathTraversalDetectorTest {

    static HttpServer s;
    static int port;

    @BeforeAll
    static void up() throws Exception {
        s = HttpServer.create(new InetSocketAddress(0), 0);
        port = s.getAddress().getPort();

        // /lfi?file=... → "../" 또는 인코딩 포함되면 /etc/passwd 흉내 본문 반환
        s.createContext("/lfi", ex -> {
            String q = ex.getRequestURI().getRawQuery();
            boolean traverse = q != null &&
                    (q.contains("..%2F") || q.contains("../") || q.contains("..%5C") || q.contains("..\\"));
            String body = traverse
                    ? "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                    : "ok";
            respond(ex, 200, "text/plain; charset=utf-8", body);
        });

        s.start();
    }

    @AfterAll
    static void down(){ s.stop(0); }

    @Test
    void detects_unix_like_signature() {
        var cfg = new ScanConfig().setMode(Mode.SAFE_PLUS);   // ★ 변경
        var engine = new ProbeEngine(cfg);
        var det = new PathTraversalDetector();

        Optional<com.webkillerai.core.model.VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:"+port+"/lfi"), "file");

        assertTrue(vr.isPresent(), "should detect LFI via path traversal");
        assertTrue(vr.get().getEvidenceSnippet().contains("root:x:0:0:"));
    }

    private static void respond(HttpExchange ex, int code, String ctype, String body) throws java.io.IOException {
        ex.getResponseHeaders().set("Content-Type", ctype);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
