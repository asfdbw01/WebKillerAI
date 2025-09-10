package com.webkillerai.core.crawler;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.util.UrlUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Crawler — extractor 예외 발생 시에도 탐색 계속")
class CrawlerResilienceTest {

    /** 간단 맵 기반 extractor: 특정 키에 대해 링크 목록 리턴 */
    static final class MapExtractor implements LinkExtractor {
        private final Map<String, List<String>> adj;
        private final Set<String> shouldThrow;

        MapExtractor(Map<String, List<String>> adj, Set<String> shouldThrow) {
            this.adj = adj;
            this.shouldThrow = shouldThrow;
        }

        @Override public Set<URI> extract(URI page) {
            String key = UrlUtils.normalize(page).toString();
            if (shouldThrow.contains(key)) throw new RuntimeException("boom: " + key);
            List<String> list = adj.getOrDefault(key, List.of());
            Set<URI> out = new LinkedHashSet<>();
            for (String s : list) out.add(UrlUtils.normalize(URI.create(s)));
            return out;
        }
    }

    private static String n(String s) { return UrlUtils.normalize(URI.create(s)).toString(); }

    @Test
    @DisplayName("seed→/ok,/bad ; /ok→/deep, /bad에서 예외 → /deep까지 도달")
    void continuesWhenChildThrows() {
        String seed = "https://ex.com/";

        var adj = new LinkedHashMap<String, List<String>>();
        adj.put(n(seed), List.of(n("https://ex.com/ok"), n("https://ex.com/bad")));
        adj.put(n("https://ex.com/ok"), List.of(n("https://ex.com/deep")));
        // /bad는 의도적으로 adj 미등록 (어차피 예외)

        var extractor = new MapExtractor(adj, Set.of(n("https://ex.com/bad")));

        ScanConfig cfg = new ScanConfig();
        cfg.setTarget(seed);
        cfg.setMaxDepth(2);
        cfg.setSameDomainOnly(true);

        var crawler = new Crawler(cfg, extractor, HttpClient.newHttpClient());
        var visited = crawler.crawlSeeds();

        var urls = visited.stream().map(u -> UrlUtils.normalize(u).toString()).toList();

        // /bad 노드는 큐에 들어가 visited엔 있음(추출 시 예외로 그 하위만 스킵), /deep은 /ok 경로로 도달
        assertThat(urls)
                .containsExactlyInAnyOrder(
                        n(seed),
                        n("https://ex.com/ok"),
                        n("https://ex.com/bad"),
                        n("https://ex.com/deep")
                );
    }

    @Test
    @DisplayName("seed에서 바로 예외 → seed만 방문 처리하고 종료")
    void seedThrows_leavesOnlySeed() {
        String seed = "https://ex.com/";

        var adj = Map.<String, List<String>>of(); // 그래프 비워도 됨
        var extractor = new MapExtractor(adj, Set.of(n(seed))); // seed에서 예외

        ScanConfig cfg = new ScanConfig();
        cfg.setTarget(seed);
        cfg.setMaxDepth(3);
        cfg.setSameDomainOnly(true);

        var crawler = new Crawler(cfg, extractor, HttpClient.newHttpClient());
        var visited = crawler.crawlSeeds();

        var urls = visited.stream().map(u -> UrlUtils.normalize(u).toString()).toList();

        assertThat(urls).containsExactly(n(seed));
    }
}
