package com.webkillerai.core.crawler.robots;

import com.webkillerai.core.crawler.robots.RobotsMatcher;
import com.webkillerai.core.crawler.robots.RobotsParser;
import com.webkillerai.core.crawler.robots.RobotsRules;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class RobotsSmokeTest {

    private static RobotsRules rules(String robotsTxt) {
        return RobotsParser.parse(robotsTxt).selectFor("WebKillerAI");
    }
    private static boolean allowed(String robotsTxt, String url) {
        return RobotsMatcher.isAllowed(URI.create(url), rules(robotsTxt));
    }

    @Test
    void prefix_block() {
        String robots = """
                User-agent: *
                Disallow: /admin
                """;
        assertFalse(allowed(robots, "https://ex.com/admin"));
        assertFalse(allowed(robots, "https://ex.com/admin/x"));
        assertTrue(allowed(robots, "https://ex.com/adm"));
    }

    @Test
    void allow_exact_with_dollar_disallow_subdir() {
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
    void wildcard_star() {
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
    void query_and_fragment_ignored() {
        String robots = """
                User-agent: *
                Disallow: /q
                """;
        assertFalse(allowed(robots, "https://ex.com/q?x=1"));
        assertFalse(allowed(robots, "https://ex.com/q#frag"));
    }

    @Test
    void percent_encoding_uppercased_no_decode() {
        String robots = """
                User-agent: *
                Disallow: /download/%2Fraw
                """;
        assertFalse(allowed(robots, "https://ex.com/download/%2Fraw")); // literal %2F
        assertTrue(allowed(robots, "https://ex.com/download/raw"));     // real slash
    }

    @Test
    void longest_match_wins_and_allow_ties() {
        String robots = """
                User-agent: *
                Disallow: /a/b
                Allow: /a/b/c
                """;
        assertTrue(allowed(robots, "https://ex.com/a/b/c"));  // longer allow
        assertFalse(allowed(robots, "https://ex.com/a/b/x")); // shorter disallow applies
    }

    @Test
    void empty_disallow_is_ignored() {
        String robots = """
                User-agent: *
                Disallow:
                """;
        assertTrue(allowed(robots, "https://ex.com/any"));
    }

    @Test
    void end_anchor_dollar() {
        String robots = """
                User-agent: *
                Disallow: /end$
                """;
        assertFalse(allowed(robots, "https://ex.com/end"));
        assertTrue(allowed(robots, "https://ex.com/end/")); // not end-of-path
    }

    @Test
    void ua_group_selection_exact_then_star() {
        String robots = """
                User-agent: Googlebot
                Disallow: /blocked-by-google

                User-agent: *
                Disallow: /blocked-all
                """;
        // 우리 UA는 WebKillerAI → '*' 그룹 사용
        assertFalse(allowed(robots, "https://ex.com/blocked-all"));
        assertTrue(allowed(robots, "https://ex.com/blocked-by-google"));
    }

    @Test
    void path_root_defaults_to_slash() {
        String robots = """
                User-agent: *
                Disallow: /$
                """;
        assertFalse(allowed(robots, "https://ex.com/"));      // exact root
        assertTrue(allowed(robots, "https://ex.com/index"));  // not root
    }

    @Test
    void star_zero_length_ok() {
        String robots = """
                User-agent: *
                Disallow: /x*/y
                """;
        assertFalse(allowed(robots, "https://ex.com/x/y"));     // '*' = ""
        assertFalse(allowed(robots, "https://ex.com/xxx/y"));   // '*' = "xx"
        assertTrue(allowed(robots, "https://ex.com/x"));        // no '/y'
    }

    @Test
    void mixed_case_percent_in_rule_is_normalized() {
        String robots = """
                User-agent: *
                Disallow: /p/%2fq
                """;
        assertFalse(allowed(robots, "https://ex.com/p/%2Fq"));
        assertFalse(allowed(robots, "https://ex.com/p/%2fq")); // rule normalized to %2F
    }

    @Test
    void disallow_vs_allow_same_length_allow_wins() {
        String robots = """
                User-agent: *
                Disallow: /same
                Allow: /same
                """;
        assertTrue(allowed(robots, "https://ex.com/same"));
    }

    @Test
    void multiple_rules_pick_longest_even_if_disallow() {
        String robots = """
                User-agent: *
                Allow: /a
                Disallow: /a/b/c
                Allow: /a/b
                """;
        assertFalse(allowed(robots, "https://ex.com/a/b/c/d")); // longest is disallow /a/b/c
        assertTrue(allowed(robots, "https://ex.com/a/b/x"));    // /a/b allow beats /a
    }
}
