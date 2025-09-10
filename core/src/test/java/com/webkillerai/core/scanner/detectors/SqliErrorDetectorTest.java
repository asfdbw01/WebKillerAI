package com.webkillerai.core.scanner.detectors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.webkillerai.core.model.Mode;            // ★ 최상위 Mode
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SqliErrorDetectorTest {

    static HttpServer s;
    static int port;

    @BeforeAll
    static void up() throws Exception {
        s = HttpServer.create(new InetSocketAddress(0), 0);
        port = s.getAddress().getPort();
        s.createContext("/sqli", SqliErrorDetectorTest::handleSqli);
        s.start();
    }

    @AfterAll
    static void down(){ s.stop(0); }

    @Test
    void detects_error_based_after_single_quote() {
        var cfg = new ScanConfig().setMode(Mode.SAFE_PLUS);        // ★ 최상위 Mode
        var engine = new ProbeEngine(cfg);
        var det = new SqliErrorDetector();

        Optional<com.webkillerai.core.model.VulnResult> vr =
                det.detect(engine, cfg, URI.create("http://localhost:"+port+"/sqli"), "id");

        assertTrue(vr.isPresent(), "should detect SQLi error");
        assertNotNull(vr.get().getEvidenceSnippet());
        assertNotNull(vr.get().getRequestLine());
    }

    private static void handleSqli(HttpExchange ex) throws java.io.IOException {
        String raw = ex.getRequestURI().getRawQuery(); // 인코딩 그대로
        // 디버그: 실제 들어온 쿼리 확인해보려면 주석 해제
        // System.out.println("[TEST] rawQuery=" + raw);

        boolean injected = containsQuote(raw);

        String body = injected
                ? "<html>ERROR: syntax error at or near \"'\"</html>"
                : "<html>ok</html>";
        respond(ex, 200, "text/html; charset=utf-8", body);
    }

    /** rawQuery에서 ' 주입을 최대 3단계 디코딩까지 감지 */
    private static boolean containsQuote(String raw) {
        if (raw == null) return false;
        String lower = raw.toLowerCase();
        // 원시(비인코딩) 또는 1~2회 인코딩 흔적 바로 감지
        if (raw.contains("'") || lower.contains("%27") || lower.contains("%2527")) return true;

        // 파라미터 값 기준으로 최대 3회 진행 디코딩하며 확인
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String v = (eq >= 0) ? pair.substring(eq + 1) : "";
            String cur = v;
            for (int i = 0; i < 3; i++) {
                String next = URLDecoder.decode(cur, StandardCharsets.UTF_8);
                if (next.equals(cur)) break;   // 더 이상 변화 없음
                cur = next;
            }
            if (cur.contains("'")) return true;
        }
        return false;
    }

    private static void respond(HttpExchange ex, int code, String ctype, String body) throws java.io.IOException {
        ex.getResponseHeaders().set("Content-Type", ctype);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
