package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.net.http.*;
import java.time.*;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 호스트별 robots.txt 캐시
 * - 기본 TTL 30분
 * - SysProp 우선: -Dwk.robots.cacheTtlMinutes=NN
 * - TTL <= 0 이면 캐시 미사용(매 요청 fetch)
 */
public class RobotsCache {

    private static final String UA = "WebKillerAI";
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(30);

    private final HttpClient http;
    private final Duration ttl;
    private final Map<String, Entry> cache = new ConcurrentHashMap<>();

    /** 기존 생성자(호환): 기본 TTL 적용 */
    public RobotsCache(HttpClient http) {
        this(http, DEFAULT_TTL);
    }

    /** NEW: TTL 주입 가능 (scan.yml 값 전달 권장) */
    public RobotsCache(HttpClient http, Duration ttlBase) {
        this.http = Objects.requireNonNull(http, "http");
        this.ttl = resolveTtl(ttlBase);
    }

    /** SysProp(-Dwk.robots.cacheTtlMinutes) 우선, 없으면 주입값→기본 */
    private static Duration resolveTtl(Duration base) {
        String v = System.getProperty("wk.robots.cacheTtlMinutes");
        if (v != null && !v.isBlank()) {
            try { return Duration.ofMinutes(Long.parseLong(v.trim())); } catch (Exception ignore) {}
        }
        return base != null ? base : DEFAULT_TTL;
    }

    /** TTL<=0 이면 캐시 비활성 */
    public RobotsPolicy policyFor(URI uri) {
        String host = uri.getHost();
        if (host == null || host.isBlank()) return RobotsPolicy.allowAll();
        String scheme = (uri.getScheme() == null || uri.getScheme().isBlank()) ? "https" : uri.getScheme();

        if (ttl.isZero() || ttl.isNegative()) {
            return fetch(host, scheme);
        }

        Entry e = cache.get(host);
        Instant now = Instant.now();
        if (e != null && e.expires.isAfter(now)) return e.policy;

        RobotsPolicy p = fetch(host, scheme);
        cache.put(host, new Entry(p, now.plus(ttl)));
        return p;
    }

    private RobotsPolicy fetch(String host, String scheme) {
        try {
            URI u = URI.create(scheme + "://" + host + "/robots.txt");
            HttpRequest req = HttpRequest.newBuilder(u)
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", UA)
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 200 && res.statusCode() < 300) {
                return RobotsPolicy.parse(res.body(), UA);
            }
        } catch (Exception ignore) {}
        return RobotsPolicy.allowAll(); // 실패 시 허용 (SAFE 기본)
    }

    private record Entry(RobotsPolicy policy, Instant expires) {}

    /** 디버그용 */
    public Duration effectiveTtl() { return ttl; }
    public void clear() { cache.clear(); }
}
