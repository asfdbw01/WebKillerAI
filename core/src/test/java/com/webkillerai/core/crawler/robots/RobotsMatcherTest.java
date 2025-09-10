package com.webkillerai.core.crawler.robots;

import com.webkillerai.core.crawler.robots.RobotsMatcher;
import com.webkillerai.core.crawler.robots.RobotsParser;
import com.webkillerai.core.crawler.robots.RobotsRules;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class RobotsMatcherTest {

    private static RobotsRules rules(String robotsTxt) {
        return RobotsParser.parse(robotsTxt).selectFor("WebKillerAI");
    }

    private static boolean allowed(String robotsTxt, String url) {
        return RobotsMatcher.isAllowed(URI.create(url), rules(robotsTxt));
    }

    @Test
    void disallow_admin_prefix() {
        String robots = """
                User-agent: *
                Disallow: /admin
                """;
        assertFalse(allowed(robots, "https://ex.com/admin"));
        assertFalse(allowed(robots, "https://ex.com/admin/settings"));
        assertTrue(allowed(robots, "https://ex.com/adm")); // 접두 불일치
    }

    @Test
    void allow_exact_admin_with_dollar_disallow_subdir() {
        String robots = """
                User-agent: *
                Allow: /admin$
                Disallow: /admin/
                """;
        assertTrue(allowed(robots, "https://ex.com/admin"));
        assertFalse(allowed(robots, "https://ex.com/admin/"));
        assertFalse(allowed(robots, "https://ex.com/admin/x"));
    }

    @Test
    void wildcard_private_star_blocks_variants() {
        String robots = """
                User-agent: *
                Disallow: /private*
                """;
        assertFalse(allowed(robots, "https://ex.com/private"));
        assertFalse(allowed(robots, "https://ex.com/privateX"));
        assertFalse(allowed(robots, "https://ex.com/private/a"));
        assertTrue(allowed(robots, "https://ex.com/priv"));
    }

    @Test
    void allow_pub_star_but_block_public_secret() {
        String robots = """
                User-agent: *
                Allow: /pub*
                Disallow: /public/secret
                """;
        assertTrue(allowed(robots, "https://ex.com/pub/a"));
        assertFalse(allowed(robots, "https://ex.com/public/secret"));
        assertTrue(allowed(robots, "https://ex.com/public/open"));
    }

    @Test
    void percent_encoding_not_decoded_slash_literal() {
        String robots = """
                User-agent: *
                Disallow: /download/%2Fraw
                """;
        // 퍼센트 인코딩은 대문자 HEX로 정규화하여 규칙과 비교(룰/URL 모두 정규화)
        assertFalse(allowed(robots, "https://ex.com/download/%2Fraw")); // 차단
        assertTrue(allowed(robots, "https://ex.com/download/raw"));     // 허용 (경로 다른 문자열)
    }

    @Test
    void percent_encoding_rule_lowercase_also_matches() {
        String robots = """
                User-agent: *
                Disallow: /p/%2fq
                """;
        // 규칙이 소문자 HEX여도 정규화되어 매칭되어야 함
        assertFalse(allowed(robots, "https://ex.com/p/%2Fq"));
        assertFalse(allowed(robots, "https://ex.com/p/%2fq"));
    }

    @Test
    void query_ignored_for_matching() {
        String robots = """
                User-agent: *
                Disallow: /q
                """;
        // 접두 매칭이므로 /q, /q?x=1, /qq 모두 차단 (쿼리는 무시)
        assertFalse(allowed(robots, "https://ex.com/q?x=1"));
        assertFalse(allowed(robots, "https://ex.com/q"));
        assertTrue(allowed(robots, "https://ex.com/qq"));
    }
    
    @Test
    void tieByDollarAllowWins() {
        String robots = String.join("\n",
            "User-agent: *",
            "Disallow: /admin",
            "Allow: /admin$"
        );
        RobotsPolicy p = RobotsPolicy.parse(robots, "WebKillerAI");
        assertTrue(p.allow(URI.create("https://ex.com/admin")));
    }
    
    @Test
    void queryIgnored_and_segmentBoundaryForPlainPrefix() {
        String robots = """
            User-agent: *
            Disallow: /q
            """;
        RobotsPolicy p = RobotsPolicy.parse(robots, "WebKillerAI");
        assertFalse(p.allow(URI.create("https://ex.com/q?x=1")));
        assertFalse(p.allow(URI.create("https://ex.com/q")));
        assertTrue(p.allow(URI.create("https://ex.com/qq"))); // 세그먼트 경계 처리
    }

}
