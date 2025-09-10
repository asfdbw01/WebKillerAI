package com.webkillerai.core.crawler;

import com.webkillerai.core.api.ICrawler;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.util.UrlExclusion;
import com.webkillerai.core.util.UrlUtils;
import com.webkillerai.core.crawler.robots.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.*;
import java.time.Duration;

/**
 * BFS 기반 Crawler
 * - sameDomainOnly / maxDepth / excludePaths / robots 존중
 * - 링크 추출은 LinkExtractor에 위임
 */
public class Crawler implements ICrawler {

    private final ScanConfig config;
    private final LinkExtractor extractor;
    private final RobotsRepository robotsRepo;
    private final boolean respectRobots;
    private static final String UA = "WebKillerAI";

    public Crawler(ScanConfig config) {
        this(config, new JsoupLinkExtractor(config.getTimeoutMs(), true));
    }

    public Crawler(ScanConfig config, LinkExtractor extractor) {
        this(config, extractor, HttpClient.newHttpClient());
    }

    public Crawler(ScanConfig config, LinkExtractor extractor, HttpClient httpClient) {
        this.config = Objects.requireNonNull(config, "config");
        this.extractor = Objects.requireNonNull(extractor, "extractor");
        int ttlMin = (config.getCrawler() != null ? config.getCrawler().getCacheTtlMinutes() : 30);
        RobotsFetcher fetcher = new HttpRobotsFetcher(Objects.requireNonNull(httpClient, "httpClient"), UA);
        RobotsClock clock = RobotsClock.SYSTEM;
        this.robotsRepo = new RobotsRepository(
        		fetcher,
        		clock,
        		Duration.ofMinutes(ttlMin),                 // ✅ 성공 TTL: 설정 반영
        		RobotsRepository.DEFAULT_FAILURE_TTL        // ✅ 실패 TTL: 10분 고정
        		);
        this.respectRobots = safeRespectRobots(config); // 기본 false
    }

    @Override
    public List<URI> crawlSeeds() {
        URI seed = UrlUtils.normalize(URI.create(config.getTarget()));
        int maxDepth = Math.max(0, config.getMaxDepth());
        boolean sameDomainOnly = config.isSameDomainOnly();
        final List<String> excludes = safeGetExcludes(config);

        Set<URI> seen = new LinkedHashSet<>();      // 중복 방지 전용
        List<URI> fetched = new ArrayList<>();      // 실제 방문(추출) 성공 목록
        Deque<Node> q = new ArrayDeque<>();
        seen.add(seed);
        q.addLast(new Node(seed, 0));

        while (!q.isEmpty()) {
            Node cur = q.pollFirst();

            // 방문(추출) 전에 robots 허용 여부 확인 — seed 포함
            if (respectRobots) {
            	var polCur = robotsRepo.policyFor(cur.uri, UA);
            	if (!polCur.allow(cur.uri)) continue;
            }

            fetched.add(cur.uri); // ✔ 실제 방문으로 카운트/반환
            
            if (cur.depth >= maxDepth) continue;

            Set<URI> links;
            try {
                links = extractor.extract(cur.uri);
            } catch (Exception ignore) {
                continue;
            }

            for (URI raw : links) {
                URI n = UrlUtils.normalize(raw);
                if (n == null) continue;

                if (sameDomainOnly && !UrlUtils.sameDomain(seed, n)) continue;

                if (!excludes.isEmpty() && UrlExclusion.isExcluded(n, excludes)) continue;

                // robots.txt 존중(큐 넣기 직전)
                if (respectRobots) {
                	var pol = robotsRepo.policyFor(n, UA);
                	if (!pol.allow(n)) continue;
                }

                if (seen.add(n)) {  // dedupe는 유지, 결과는 방문 시점에만 추가
                    q.addLast(new Node(n, cur.depth + 1));
                }
            }
        }
        return fetched;
    }

    // config 구조가 달라도 안전하게 읽기 (기본 빈 리스트)
    @SuppressWarnings("unchecked")
    private static List<String> safeGetExcludes(ScanConfig cfg) {
        try {
            var m = cfg.getClass().getMethod("getExcludePaths");
            Object v = m.invoke(cfg);
            if (v instanceof List) return (List<String>) v;
        } catch (Exception ignore) {
            try {
                var mCrawler = cfg.getClass().getMethod("getCrawler");
                Object crawler = mCrawler.invoke(cfg);
                if (crawler != null) {
                    var m2 = crawler.getClass().getMethod("getExcludePaths");
                    Object v2 = m2.invoke(crawler);
                    if (v2 instanceof List) return (List<String>) v2;
                }
            } catch (Exception ignored) {}
        }
        return Collections.emptyList();
    }

    // config 구조가 달라도 안전하게 읽기 (기본 false)
    private static boolean safeRespectRobots(ScanConfig cfg) {
        try {
            var m = cfg.getClass().getMethod("isRespectRobots");
            Object v = m.invoke(cfg);
            return v instanceof Boolean && (Boolean) v;
        } catch (Exception ignore) {
            try {
                var mCrawler = cfg.getClass().getMethod("getCrawler");
                Object crawler = mCrawler.invoke(cfg);
                if (crawler != null) {
                    var m2 = crawler.getClass().getMethod("isRespectRobots");
                    Object v2 = m2.invoke(crawler);
                    return v2 instanceof Boolean && (Boolean) v2;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }

    private static final class Node {
        final URI uri; final int depth;
        Node(URI u, int d) { this.uri = u; this.depth = d; }
    }
}
