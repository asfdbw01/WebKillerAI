package com.webkillerai.core.crawler;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.util.UrlUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Crawler — BFS depth & same-domain filtering")
class CrawlerDepthAndDomainTest {

    /** 간단한 그래프형 Extractor: 페이지별 링크 맵 리턴 */
    static final class MapExtractor implements LinkExtractor {
        private final Map<String, List<String>> adj;
        MapExtractor(Map<String, List<String>> adj) { this.adj = adj; }
        @Override public Set<URI> extract(URI page) {
            var key = UrlUtils.normalize(page).toString();
            var list = adj.getOrDefault(key, List.of());
            Set<URI> out = new LinkedHashSet<>();
            for (String s : list) out.add(UrlUtils.normalize(URI.create(s)));
            return out;
        }
    }

    private static String n(String s) { return UrlUtils.normalize(URI.create(s)).toString(); }

    @Test
    @DisplayName("maxDepth=1 이면 seed의 1-hop까지만 탐색, 외부 도메인은 제외")
    void depth1_sameDomainOnly() {
        // 그래프:
        //   /        -> /a, /b, https://other.com/x
        //   /a       -> /a/aa
        //   /b       -> (없음)
        String seed = "https://ex.com/";
        var adj = new LinkedHashMap<String, List<String>>();
        adj.put(n(seed), List.of(n("https://ex.com/a"), n("https://ex.com/b"), n("https://other.com/x")));
        adj.put(n("https://ex.com/a"), List.of(n("https://ex.com/a/aa")));
        adj.put(n("https://ex.com/b"), List.of());

        var extractor = new MapExtractor(adj);

        ScanConfig cfg = new ScanConfig();
        cfg.setTarget(seed);
        cfg.setMaxDepth(1);
        cfg.setSameDomainOnly(true);

        var crawler = new Crawler(cfg, extractor, HttpClient.newHttpClient());
        var visited = crawler.crawlSeeds();

        var urls = visited.stream().map(u -> UrlUtils.normalize(u).toString()).toList();

        assertThat(urls)
                .contains(n(seed), n("https://ex.com/a"), n("https://ex.com/b"))
                .doesNotContain(n("https://other.com/x"), n("https://ex.com/a/aa")); // depth=1이라 /a/aa 미포함
    }

    @Test
    @DisplayName("maxDepth=2 이면 /a/aa 까지 포함 (여전히 외부 도메인은 제외)")
    void depth2_includesSecondHop() {
        String seed = "https://ex.com/";
        var adj = new LinkedHashMap<String, List<String>>();
        adj.put(n(seed), List.of(n("https://ex.com/a"), n("https://ex.com/b"), n("https://other.com/x")));
        adj.put(n("https://ex.com/a"), List.of(n("https://ex.com/a/aa")));
        adj.put(n("https://ex.com/b"), List.of());

        var extractor = new MapExtractor(adj);

        ScanConfig cfg = new ScanConfig();
        cfg.setTarget(seed);
        cfg.setMaxDepth(2);
        cfg.setSameDomainOnly(true);

        var crawler = new Crawler(cfg, extractor, HttpClient.newHttpClient());
        var visited = crawler.crawlSeeds();

        var urls = visited.stream().map(u -> UrlUtils.normalize(u).toString()).toList();

        assertThat(urls)
                .contains(n(seed), n("https://ex.com/a"), n("https://ex.com/b"), n("https://ex.com/a/aa"))
                .doesNotContain(n("https://other.com/x"));
    }
    
    @Test
    @DisplayName("sameDomainOnly=false → 다른 도메인 링크도 방문됨")
    void sameDomainOnlyFalse_keepsOtherDomains() {
        String seed = "https://ex.com/";
        var adj = new LinkedHashMap<String, List<String>>();
        adj.put(n(seed), List.of(n("https://ex.com/in"), n("https://other.com/out")));

        var extractor = new MapExtractor(adj);

        ScanConfig cfg = new ScanConfig();
        cfg.setTarget(seed);
        cfg.setMaxDepth(1);
        cfg.setSameDomainOnly(false);  // 교차 도메인 허용

        var crawler = new Crawler(cfg, extractor, HttpClient.newHttpClient());
        var urls = crawler.crawlSeeds().stream().map(u -> UrlUtils.normalize(u).toString()).toList();

        assertThat(urls)
                .contains(n(seed), n("https://ex.com/in"), n("https://other.com/out"));
    }

    @Test
    @DisplayName("중복 링크 제거 — 여러 경로가 동일 URL을 가리켜도 1회만 방문")
    void deDuplicatesUrls() {
        String seed = "https://ex.com/";
        var adj = new LinkedHashMap<String, List<String>>();
        adj.put(n(seed), List.of(n("https://ex.com/a"), n("https://ex.com/b")));
        adj.put(n("https://ex.com/a"), List.of(n("https://ex.com/x")));
        adj.put(n("https://ex.com/b"), List.of(n("https://ex.com/x"))); // 중복

        var extractor = new MapExtractor(adj);

        ScanConfig cfg = new ScanConfig();
        cfg.setTarget(seed);
        cfg.setMaxDepth(2);
        cfg.setSameDomainOnly(true);

        var crawler = new Crawler(cfg, extractor, HttpClient.newHttpClient());
        var urls = crawler.crawlSeeds().stream().map(u -> UrlUtils.normalize(u).toString()).toList();

        // /x는 한 번만 포함되면 됨
        assertThat(urls)
                .contains(n(seed), n("https://ex.com/a"), n("https://ex.com/b"), n("https://ex.com/x"));
    }
}
