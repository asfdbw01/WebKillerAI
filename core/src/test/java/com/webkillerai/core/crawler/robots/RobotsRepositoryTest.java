package com.webkillerai.core.crawler.robots;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class RobotsRepositoryTest {

    @Test
    void success_cached_30m() {
        URI page = URI.create("https://ex.com/path");
        URI robots = URI.create("https://ex.com/robots.txt");
        String txt = "User-agent: *\nDisallow: /private\n";

        FakeFetcher f = new FakeFetcher().stub(robots, 200, txt);
        FrozenClock clk = new FrozenClock(0);
        RobotsRepository repo = new RobotsRepository(f, clk);

        RobotsPolicy p1 = repo.policyFor(page, "WebKillerAI");
        assertFalse(p1.allow(URI.create("https://ex.com/private"))); // 차단
        // 캐시 유지 확인(재페치 없음): 스텁 제거해도 동작
        f = new FakeFetcher(); // 일부러 비움
        clk.plusMillis(Duration.ofMinutes(29).toMillis());
        RobotsPolicy p2 = repo.policyFor(page, "WebKillerAI");
        assertFalse(p2.allow(URI.create("https://ex.com/private")));
    }

    @Test
    void failure_404_allowAll_cached_10m() {
        URI page = URI.create("https://ex.com/x");
        URI robots = URI.create("https://ex.com/robots.txt");

        FakeFetcher f = new FakeFetcher().stub(robots, 404, "");
        FrozenClock clk = new FrozenClock(0);
        RobotsRepository repo = new RobotsRepository(f, clk);

        RobotsPolicy p = repo.policyFor(page, "WebKillerAI");
        assertTrue(p.allow(URI.create("https://ex.com/any"))); // allow-all

        // 9분59초 내 재조회 시 캐시 히트(재페치 없음)
        clk.plusMillis(Duration.ofMinutes(9).plusSeconds(59).toMillis());
        RobotsPolicy p2 = repo.policyFor(page, "WebKillerAI");
        assertTrue(p2.allow(URI.create("https://ex.com/any")));
    }

    @Test
    void redirect_same_host_followed() {
        URI page = URI.create("http://ex.com/x");
        URI robotsHttp = URI.create("http://ex.com/robots.txt");
        URI robotsHttps = URI.create("https://ex.com/robots.txt");
        String txt = "User-agent: *\nDisallow: /q\n";

        FakeFetcher f = new FakeFetcher()
                .redirect(robotsHttp, robotsHttps, 301)
                .stub(robotsHttps, 200, txt);
        FrozenClock clk = new FrozenClock(0);
        RobotsRepository repo = new RobotsRepository(f, clk);

        RobotsPolicy p = repo.policyFor(page, "WebKillerAI");
        assertFalse(p.allow(URI.create("https://ex.com/q?a=1"))); // 차단
    }

    @Test
    void redirect_cross_host_fails_allowAll() {
        URI page = URI.create("https://a.com/x");
        URI robotsA = URI.create("https://a.com/robots.txt");
        URI robotsB = URI.create("https://b.com/robots.txt");

        FakeFetcher f = new FakeFetcher().redirect(robotsA, robotsB, 302);
        FrozenClock clk = new FrozenClock(0);
        RobotsRepository repo = new RobotsRepository(f, clk);

        RobotsPolicy p = repo.policyFor(page, "WebKillerAI");
        assertTrue(p.allow(URI.create("https://a.com/anything"))); // allow-all
    }
}
