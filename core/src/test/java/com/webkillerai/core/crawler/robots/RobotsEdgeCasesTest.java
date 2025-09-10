// core/src/test/java/com/webkillerai/core/crawler/RobotsEdgeCasesTest.java
package com.webkillerai.core.crawler.robots;

import com.webkillerai.core.crawler.robots.RobotsMatcher;
import com.webkillerai.core.crawler.robots.RobotsParser;
import com.webkillerai.core.crawler.robots.RobotsRules;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class RobotsEdgeCasesTest {

    private static RobotsRules rules(String robotsTxt) {
        return RobotsParser.parse(robotsTxt).selectFor("WebKillerAI");
    }
    private static boolean allowed(String robotsTxt, String url) {
        return RobotsMatcher.isAllowed(URI.create(url), rules(robotsTxt));
    }

    @Test
    void tie_same_length_allow_wins() {
        String robots = """
                User-agent: *
                Disallow: /same
                Allow: /same
                """;
        assertTrue(allowed(robots, "https://ex.com/same"));
    }

    @Test
    void percent_hex_rule_mixed_case_normalized() {
        String robots = """
                User-agent: *
                Disallow: /p/%2fq
                """;
        assertFalse(allowed(robots, "https://ex.com/p/%2Fq")); // URL 대문자
        assertFalse(allowed(robots, "https://ex.com/p/%2fq")); // URL 소문자
        assertTrue(allowed(robots, "https://ex.com/p//q"));    // 실제 슬래시는 불일치
    }

    @Test
    void end_anchor_applies_to_path_end_only() {
        String robots = """
                User-agent: *
                Disallow: /root$
                """;
        assertFalse(allowed(robots, "https://ex.com/root"));
        assertTrue(allowed(robots, "https://ex.com/root/next"));
    }

    @Test
    void star_can_match_zero_length() {
        String robots = """
                User-agent: *
                Disallow: /x*/y
                """;
        assertFalse(allowed(robots, "https://ex.com/x/y"));    // * = ""
        assertFalse(allowed(robots, "https://ex.com/xxx/y"));  // * = "xx"
        assertTrue(allowed(robots, "https://ex.com/x"));       // 뒤에 /y 없음
    }

    @Test
    void longest_match_disallow_overrides_shorter_allow() {
        String robots = """
                User-agent: *
                Allow: /a/b
                Disallow: /a/b/c
                """;
        assertFalse(allowed(robots, "https://ex.com/a/b/c"));   // 더 긴 disallow
        assertTrue(allowed(robots, "https://ex.com/a/b/x"));    // allow 매치
    }

    @Test
    void empty_disallow_is_ignored() {
        String robots = """
                User-agent: *
                Disallow:
                Allow: /open
                """;
        assertTrue(allowed(robots, "https://ex.com/open"));
        assertTrue(allowed(robots, "https://ex.com/anything")); // 비어있는 Disallow는 무시
    }
}
