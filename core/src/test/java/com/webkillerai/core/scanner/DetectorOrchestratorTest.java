// src/test/java/com/webkillerai/core/scanner/DetectorOrchestratorTest.java
package com.webkillerai.core.scanner;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.util.RateLimiter;
import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class DetectorOrchestratorTest {
  static HttpServer s;
  static int port;

  @BeforeAll
  static void up() throws Exception {
    s = HttpServer.create(new InetSocketAddress("localhost", 0), 0);

    s.createContext("/", ex -> {
      String html = """
        <html><body>
          <a href="/reflect?q=hello">reflect</a>
          <a href="/sqli?id=1">sqli</a>
          <form method="GET" action="/sqli">
            <input type="text" name="id" value="1">
            <button type="submit">go</button>
          </form>
          <script>var api="/x.js?cat=1"; const s="?x=1";</script>
          <link rel="next" href="/next?page=2">
        </body></html>
      """;
      respond(ex, 200, "text/html; charset=utf-8", html);
    });

    s.createContext("/reflect", ex -> {
      String q = ex.getRequestURI().getRawQuery();
      String v = q!=null && q.contains("=") ? q.substring(q.indexOf('=')+1) : "";
      String decoded = URLDecoder.decode(v, StandardCharsets.UTF_8);
      String body = "<html><body>" + decoded + "</body></html>";
      respond(ex, 200, "text/html; charset=utf-8", body);
    });

    // 유지하되, 이 테스트 파일에선 사용하지 않음 (SQLi 단위 테스트에서 이미 커버)
    s.createContext("/sqli", ex -> {
      String raw = ex.getRequestURI().getRawQuery();
      String dec = raw == null ? "" : URLDecoder.decode(raw, StandardCharsets.UTF_8);
      boolean bad = (raw != null && raw.contains("id=%27")) ||
                    dec.matches("(?s).*(?:^|[&?])id=[^&]*'.*");
      String body = bad ? "<html>ERROR: syntax error at or near \"'\"</html>" : "<html>ok</html>";
      respond(ex, 200, "text/html; charset=utf-8", body);
    });

    s.createContext("/cors-bad", ex -> {
      if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
        ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().add("Access-Control-Allow-Credentials", "true");
        respondNoBody(ex, 204, "text/plain");
      } else {
        respond(ex, 200, "text/plain; charset=utf-8", "ok");
      }
    });

    s.start();
    port = s.getAddress().getPort();
  }

  @AfterAll static void down(){ if (s != null) s.stop(0); }

  // ✅ 오케스트레이터 종합 테스트는 “안정적인 비주입형”만 검증
  @Test
  void orchestrator_catches_cors_on_endpoint() {
    var cfg = new ScanConfig().setMode(Mode.SAFE_PLUS);
    var rl  = new RateLimiter(1000, 1000);
    var orch = new DetectorOrchestrator(cfg, rl);

    var results = orch.scan(URI.create("http://localhost:"+port+"/cors-bad"));
    assertTrue(results.stream().anyMatch(v -> v.getIssueType()== IssueType.CORS_MISCONFIG));
  }

  /*  ---- helpers ---- */

  private static void respond(HttpExchange ex, int code, String ctype, String body) throws java.io.IOException {
    ex.getResponseHeaders().set("Content-Type", ctype);
    byte[] b = body.getBytes(StandardCharsets.UTF_8);
    ex.sendResponseHeaders(code, b.length);
    try (OutputStream os = ex.getResponseBody()) { os.write(b); }
  }

  private static void respondNoBody(HttpExchange ex, int code, String ctype) throws java.io.IOException {
    ex.getResponseHeaders().set("Content-Type", ctype);
    ex.sendResponseHeaders(code, -1);
    ex.close();
  }
}
