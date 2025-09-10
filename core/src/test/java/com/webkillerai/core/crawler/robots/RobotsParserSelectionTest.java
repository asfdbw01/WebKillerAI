package com.webkillerai.core.crawler.robots;

import com.webkillerai.core.crawler.robots.RobotsMatcher;
import com.webkillerai.core.crawler.robots.RobotsParser;
import com.webkillerai.core.crawler.robots.RobotsRules;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class RobotsParserSelectionTest {

    private static boolean allowed(String ua, String robotsTxt, String url) {
        RobotsRules rules = RobotsParser.parse(robotsTxt).selectFor(ua);
        return RobotsMatcher.isAllowed(URI.create(url), rules);
    }

    @Test
    void longest_user_agent_match_wins_then_star() {
        String robots = """
                User-agent: *
                Disallow: /all

                User-agent: killer
                Allow: /

                User-agent: WebKillerAI
                Disallow: /only-for-wk
                """;

        // 정확 매칭: WebKillerAI 규칙 적용
        assertFalse(allowed("WebKillerAI", robots, "https://ex.com/only-for-wk"));
        assertTrue(allowed("WebKillerAI", robots, "https://ex.com/free"));

        // 부분 매칭: "killer"가 * 보다 더 김 → killer 규칙 적용(Allow: /)
        assertTrue(allowed("my-killer-bot", robots, "https://ex.com/anything"));

        // 정의 없는 UA → '*' 규칙 적용
        assertFalse(allowed("SomeOtherBot", robots, "https://ex.com/all/blocked"));
    }
}
