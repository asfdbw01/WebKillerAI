// src/test/java/com/webkillerai/core/crawler/robots/RobotsParserTest.java
package com.webkillerai.core.crawler.robots;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class RobotsParserTest {

    private static RobotsRules rules(String robotsTxt, String ua) {
        return RobotsParser.parse(robotsTxt).selectFor(ua);
    }
    private static boolean allowed(String url, RobotsRules r) {
        return RobotsMatcher.isAllowed(URI.create(url), r);
    }

    @Test
    void multiUserAgent_grouping_and_emptyDisallowIgnored() {
        String robots = """
                # group 1: Alpha & Beta
                User-agent: AlphaBot
                User-agent: BetaBot
                Disallow: /private
                Allow: /public$

                # star group
                User-agent: *
                Disallow: /tmp
                Disallow: /download/%2Fraw
                """;

        RobotsRules beta = rules(robots, "BetaBot");
        assertFalse(allowed("https://ex.com/private", beta));
        assertTrue (allowed("https://ex.com/public",  beta));
        assertTrue (allowed("https://ex.com/public/", beta)); // 규칙 미일치 → 허용

        RobotsRules other = rules(robots, "OtherUA");
        assertFalse(allowed("https://ex.com/tmp", other));
        assertTrue (allowed("https://ex.com/anything", other));

        // percent-hex literal (star 그룹) → 리터럴로만 매칭
        assertFalse(allowed("https://ex.com/download/%2Fraw", other));
        assertTrue (allowed("https://ex.com/download//raw",   other));
    }

    @Test
    void selectGroup_exact_match_then_fallback_star() {
        String robots = """
                User-agent: MyBot
                Disallow: /x

                User-agent: *
                Disallow: /tmp
                """;

        // 정확 매치: "MyBot" → MyBot 그룹 규칙 적용
        RobotsRules mybotExact = RobotsParser.parse(robots).selectFor("MyBot");
        assertFalse(RobotsMatcher.isAllowed(URI.create("https://ex.com/x"),   mybotExact));
        assertTrue (RobotsMatcher.isAllowed(URI.create("https://ex.com/tmp"), mybotExact));
        assertTrue (RobotsMatcher.isAllowed(URI.create("https://ex.com/ok"),  mybotExact));

        // 부분 문자열 UA: "MyBot/1.0" → 정확 매치 없으므로 '*' 그룹 적용
        RobotsRules mybotWithVersion = RobotsParser.parse(robots).selectFor("MyBot/1.0");
        assertTrue (RobotsMatcher.isAllowed(URI.create("https://ex.com/x"),   mybotWithVersion));  // * 그룹이라 /x 허용
        assertFalse(RobotsMatcher.isAllowed(URI.create("https://ex.com/tmp"), mybotWithVersion));  // /tmp 차단
        assertTrue (RobotsMatcher.isAllowed(URI.create("https://ex.com/ok"),  mybotWithVersion));
    }

}
