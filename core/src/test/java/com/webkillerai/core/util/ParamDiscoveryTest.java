package com.webkillerai.core.util;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ParamDiscoveryTest {

    @Test
    void discover_from_links_forms_scripts_and_url() {
        String html = """
            <html><body>
              <a href="/search?q=hello&ref=utm">link</a>
              <form method="GET" action="/find">
                <input type="text" name="query">
                <input type="hidden" name="utm_source" value="x">
              </form>
              <div data-user="42" data-page-id="777"></div>
              <script>
                var u = "/api?cat=1&gclid=zzz";
                // another script param:
                const s = "?id=100&x=1";
              </script>
            </body></html>
            """;
        URI base = URI.create("https://example.com/list?foo=1&bar=2");

        List<String> names = ParamDiscovery.discoverParamNames(base, html);

        // 포함 기대: q, query, user, page-id, cat, id, x, foo, bar (순서는 우선순위 기반)
        assertTrue(names.contains("q"));
        assertTrue(names.contains("query"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("page-id"));
        assertTrue(names.contains("cat"));
        assertTrue(names.contains("id"));
        assertTrue(names.contains("x"));
        assertTrue(names.contains("foo"));
        assertTrue(names.contains("bar"));

        // 노이즈 제거 확인
        assertFalse(names.contains("utm_source"));
        assertFalse(names.contains("gclid"));
        assertFalse(names.contains("ref"));
    }

    @Test
    void robust_when_html_null_or_malformed() {
        URI base = URI.create("https://ex.com/p?q=1&aid=2");
        List<String> names = ParamDiscovery.discoverParamNames(base, null);
        assertTrue(names.contains("q"));
        assertTrue(names.contains("aid"));
    }
}
