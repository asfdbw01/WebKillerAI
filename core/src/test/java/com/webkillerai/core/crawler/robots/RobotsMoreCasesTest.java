// src/test/java/com/webkillerai/core/crawler/RobotsMoreCasesTest.java
package com.webkillerai.core.crawler.robots;

import com.webkillerai.core.crawler.robots.RobotsMatcher;
import com.webkillerai.core.crawler.robots.RobotsParser;
import com.webkillerai.core.crawler.robots.RobotsRules;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class RobotsMoreCasesTest {
    private static RobotsRules rules(String robotsTxt) {
        return RobotsParser.parse(robotsTxt).selectFor("WebKillerAI");
    }
    private static boolean allowed(String robotsTxt, String url) {
        return RobotsMatcher.isAllowed(URI.create(url), rules(robotsTxt));
    }

    @Test void comment_and_spaces_ignored() {
        String robots = """
            User-agent: *
            Disallow:   /admin   # trailing comment
            """;
        assertFalse(allowed(robots, "https://ex.com/admin"));
    }

    @Test void empty_allow_ignored() {
        String robots = """
            User-agent: *
            Allow:
            Disallow: /x
            """;
        assertFalse(allowed(robots, "https://ex.com/x"));
    }

    @Test void allow_wins_on_tie() {
        String robots = """
            User-agent: *
            Disallow: /same
            Allow: /same
            """;
        assertTrue(allowed(robots, "https://ex.com/same"));
    }

    @Test void longest_disallow_beats_shorter_allow() {
        String robots = """
            User-agent: *
            Allow: /a
            Disallow: /a/b/c
            """;
        assertFalse(allowed(robots, "https://ex.com/a/b/c"));
    }

    @Test void star_zero_length_and_multi_segments() {
        String robots = """
            User-agent: *
            Disallow: /x*/y
            """;
        assertFalse(allowed(robots, "https://ex.com/x/y"));
        assertFalse(allowed(robots, "https://ex.com/xx/y"));
        assertTrue(allowed(robots, "https://ex.com/x"));
    }

    @Test void end_anchor_only_at_path_end() {
        String robots = """
            User-agent: *
            Disallow: /end$
            """;
        assertFalse(allowed(robots, "https://ex.com/end"));
        assertTrue(allowed(robots, "https://ex.com/end/next"));
    }

    @Test void query_and_fragment_ignored() {
        String robots = """
            User-agent: *
            Disallow: /q
            """;
        assertFalse(allowed(robots, "https://ex.com/q?x=1"));
        assertFalse(allowed(robots, "https://ex.com/q#frag"));
    }

    @Test void percent_encoding_literal_vs_real_slash() {
        String robots = """
            User-agent: *
            Disallow: /download/%2Fraw
            """;
        assertFalse(allowed(robots, "https://ex.com/download/%2Fraw"));
        assertTrue(allowed(robots, "https://ex.com/download/raw"));
    }

    @Test void percent_encoding_rule_normalized_mixed_case() {
        String robots = """
            User-agent: *
            Disallow: /p/%2fq
            """;
        assertFalse(allowed(robots, "https://ex.com/p/%2Fq"));
        assertFalse(allowed(robots, "https://ex.com/p/%2fq"));
    }

    @Test void ua_group_selection_exact_then_star() {
        String robots = """
            User-agent: OtherBot
            Disallow: /x

            User-agent: *
            Disallow: /y
            """;
        assertFalse(allowed(robots, "https://ex.com/y"));
        assertTrue(allowed(robots, "https://ex.com/x"));
    }

    @Test void root_dollar() {
        String robots = """
            User-agent: *
            Disallow: /$
            """;
        assertFalse(allowed(robots, "https://ex.com/"));
        assertTrue(allowed(robots, "https://ex.com/index"));
    }

    @Test void wildcard_prefix_suffix() {
        String robots = """
            User-agent: *
            Disallow: /*.php$
            """;
        assertFalse(allowed(robots, "https://ex.com/a.php"));
        assertFalse(allowed(robots, "https://ex.com/x/y/b.php?z=1"));
        assertTrue(allowed(robots, "https://ex.com/a.phpx"));
    }

    @Test void multiple_user_agent_lines_in_group() {
        // 그룹 경계 명확화를 위해 빈 줄 추가 (파서들이 이 구분을 기대하는 경우가 많음)
        String robots = """
            User-agent: A
            User-agent: B
            Disallow: /blocked

            User-agent: *
            Allow: /
            """;
        assertTrue(allowed(robots, "https://ex.com/blocked"));
    }

    @Test void disallow_prefix_not_partial_of_segment() {
        String robots = """
            User-agent: *
            Disallow: /admin
            """;
        assertTrue(allowed(robots, "https://ex.com/adm")); // 접두 불일치
    }

    @Test void sitemap_ignored() {
        String robots = """
            User-agent: *
            Disallow: /x
            Sitemap: https://ex.com/sitemap.xml
            """;
        assertFalse(allowed(robots, "https://ex.com/x"));
    }

    @Test void crlf_and_blank_lines() {
        String robots = "User-agent: *\r\nDisallow: /x\r\n\r\n";
        assertFalse(allowed(robots, "https://ex.com/x"));
    }

    @Disabled("NBSP(\\u00A0) 트림 미지원 — 파서 보완 시 해제")
    @Test void unicode_whitespace_trim() {
        String robots = "User-agent:\u00A0*\nDisallow:\u00A0/x\n";
        assertFalse(allowed(robots, "https://ex.com/x"));
    }

    @Test void no_rules_all_allowed() {
        String robots = "";
        assertTrue(allowed(robots, "https://ex.com/any"));
    }
}
