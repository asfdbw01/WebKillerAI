package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class RobotsRepository {

    // 기본 TTL (설정으로 오버라이드 가능)
    public static final Duration DEFAULT_SUCCESS_TTL = Duration.ofMinutes(30);
    public static final Duration DEFAULT_FAILURE_TTL = Duration.ofMinutes(10);
    private static final int MAX_REDIRECTS = 3;

    private final RobotsFetcher fetcher;
    private final RobotsClock clock;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    private final Duration successTtl;
    private final Duration failureTtl;

    // 기본 생성자: 기본 TTL 사용
    public RobotsRepository(RobotsFetcher fetcher, RobotsClock clock) {
        this(fetcher, clock, DEFAULT_SUCCESS_TTL, DEFAULT_FAILURE_TTL);
    }

    // 설정 주입 생성자: 성공 TTL/실패 TTL 주입 가능
    public RobotsRepository(RobotsFetcher fetcher, RobotsClock clock,
                            Duration successTtl, Duration failureTtl) {
        this.fetcher = Objects.requireNonNull(fetcher);
        this.clock = Objects.requireNonNull(clock);
        this.successTtl = (successTtl == null ? DEFAULT_SUCCESS_TTL : successTtl);
        this.failureTtl = (failureTtl == null ? DEFAULT_FAILURE_TTL : failureTtl);
    }

    /** host:port 키 (포트 없으면 스킴 기본포트 사용). */
    static String cacheKey(URI pageUri) {
        String scheme = Optional.ofNullable(pageUri.getScheme()).orElse("https").toLowerCase(Locale.ROOT);
        String host = Optional.ofNullable(pageUri.getHost()).orElse("").toLowerCase(Locale.ROOT);
        int port = pageUri.getPort();
        if (port < 0) port = scheme.equals("http") ? 80 : 443;
        return host + ":" + port;
    }

    /** pageUri 기준 robots 정책을 가져온다(캐시 사용). 실패 시 allow-all. */
    public RobotsPolicy policyFor(URI pageUri, String userAgent) {
        String key = cacheKey(pageUri);
        CacheEntry e = cache.get(key);
        long now = clock.nowMillis();

        if (e != null && e.expiresAt > now) {
            return e.policy;
        }

        RobotsPolicy policy = fetchAndBuildPolicy(pageUri, userAgent);
        long ttlMs = policy.isAllowAll() ? failureTtl.toMillis() : successTtl.toMillis();
        cache.put(key, new CacheEntry(policy, now + ttlMs));
        return policy;
    }

    private RobotsPolicy fetchAndBuildPolicy(URI pageUri, String userAgent) {
        // http/https만
        String scheme = Optional.ofNullable(pageUri.getScheme()).orElse("").toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return RobotsPolicy.allowAll();
        }

        URI robots = robotsTxtUri(pageUri);
        if (robots == null) { // 호스트 없는 경우
            return RobotsPolicy.allowAll();
        }

        URI cur = robots;
        for (int i = 0; i < MAX_REDIRECTS; i++) {
            RobotsFetcher.Response r = fetcher.fetch(cur);
            if (r.status == 0) {
                return RobotsPolicy.allowAll(); // 네트워크 오류
            }
            int s = r.status;

            // 성공군
            if (s >= 200 && s < 300) {
                String txt = (r.body == null) ? "" : r.body;
                return RobotsPolicy.parse(txt, userAgent);
            }

            // 리다이렉트
            if (isRedirect(s) && r.finalUri != null) {
                URI next = r.finalUri;
                // 동일 호스트 내에서만 허용(스킴 전환 OK, 포트 비교하지 않음)
                if (sameHost(cur, next)) {
                    cur = next;
                    continue;
                } else {
                    return RobotsPolicy.allowAll(); // 크로스-호스트 리다이렉트는 실패 간주
                }
            }

            // 404/410/5xx 등: 실패 → allow-all
            if (s == 404 || s == 410 || s >= 500) {
                return RobotsPolicy.allowAll();
            }
            // 그 외 예외 상태: 보수적으로 allow-all
            return RobotsPolicy.allowAll();
        }
        // too many redirects
        return RobotsPolicy.allowAll();
    }

    private static boolean isRedirect(int s) {
        return s == 301 || s == 302 || s == 307 || s == 308;
    }

    private static boolean sameHost(URI a, URI b) {
        String ha = Optional.ofNullable(a.getHost()).orElse("").toLowerCase(Locale.ROOT);
        String hb = Optional.ofNullable(b.getHost()).orElse("").toLowerCase(Locale.ROOT);
        return ha.equals(hb);
    }

    private static URI robotsTxtUri(URI page) {
        String host = page.getHost();
        if (host == null || host.isEmpty()) return null;
        String scheme = Optional.ofNullable(page.getScheme()).orElse("https");
        int port = page.getPort();
        String authority = (port < 0) ? host : host + ":" + port;
        return URI.create(scheme + "://" + authority + "/robots.txt");
    }

    private static final class CacheEntry {
        final RobotsPolicy policy;
        final long expiresAt;
        CacheEntry(RobotsPolicy p, long exp) { this.policy = p; this.expiresAt = exp; }
    }
}
