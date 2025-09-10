package com.webkillerai.core.crawler;

import com.webkillerai.core.model.ScanConfig;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class CrawlerBfsTest {

    @Test
    void bfs_sameDomain_maxDepth_dedup_and_normalize() {
        // ScanConfig: flat 구조에 맞춤
        ScanConfig cfg = ScanConfig.defaults()
                .setTarget("http://Example.com/")  // host 대소문자 섞음
                .setMaxDepth(2)
                .setSameDomainOnly(true);

        // 가짜 링크 그래프
        URI A = URI.create("http://example.com/");
        URI B = URI.create("http://EXAMPLE.com:80/b");   // 기본포트 80 → 제거되어야 함
        URI C = URI.create("http://example.com/c#frag"); // fragment 제거되어야 함
        URI D = URI.create("http://other.com/d");        // 타 도메인 → 제외

        Map<URI, Set<URI>> graph = new HashMap<>();
        graph.put(A, Set.of(B, C, D, A)); // 자기 자신/타도메인/중복 포함
        graph.put(B, Set.of());           // leaf
        graph.put(C, Set.of());           // leaf

        // JSoup 없이 주입 가능한 페이크 추출기
        LinkExtractor fake = base -> graph.getOrDefault(base, Set.of());

        // 테스트 대상
        Crawler crawler = new Crawler(cfg, fake);
        List<URI> visited = crawler.crawlSeeds();

        // 정규화된 기대 값
        URI nA = URI.create("http://example.com/");
        URI nB = URI.create("http://example.com/b");   // :80 제거
        URI nC = URI.create("http://example.com/c");   // #frag 제거

        // 포함/제외 검증
        assertTrue(visited.contains(nA), "seed should be included");
        assertTrue(visited.contains(nB), "normalized B should be visited");
        assertTrue(visited.contains(nC), "normalized C should be visited");
        assertFalse(visited.contains(D), "other domain must be excluded");

        // 중복 제거로 총 3개여야 함
        assertEquals(3, visited.size(), "visited size should be 3");
    }
}
