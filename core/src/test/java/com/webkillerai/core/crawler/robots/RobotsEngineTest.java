package com.webkillerai.core.crawler.robots;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RobotsEngineTest {

    private static Map<String, RobotsEngine.UaGroup> groupForUA(String ua, List<RobotsEngine.Rule> rules) {
        return Map.of(ua, new RobotsEngine.UaGroup(ua, rules), "*", new RobotsEngine.UaGroup("*", List.of()));
    }

    @Test
    void percentHex_isLiteral_notDecoded() {
        var rules = List.of(
                RobotsEngine.compileRule(RobotsEngine.RuleType.DISALLOW, "/download/%2Fraw")
        );
        var gmap = groupForUA("WebKillerAI", rules);

        assertFalse(RobotsEngine.isAllowed("https://ex.com/download/%2Fraw", "WebKillerAI", gmap));
        assertTrue (RobotsEngine.isAllowed("https://ex.com/download//raw",   "WebKillerAI", gmap));
    }

    @Test
    void endAnchor_dollar_onlyExactPathAllowed() {
        var rules = List.of(
                RobotsEngine.compileRule(RobotsEngine.RuleType.ALLOW, "/admin$"),
                RobotsEngine.compileRule(RobotsEngine.RuleType.DISALLOW, "/admin*")
        );
        var gmap = groupForUA("ua", rules);

        assertTrue (RobotsEngine.isAllowed("https://ex.com/admin",   "ua", gmap));
        assertFalse(RobotsEngine.isAllowed("https://ex.com/admin/",  "ua", gmap));
        assertFalse(RobotsEngine.isAllowed("https://ex.com/admin/p", "ua", gmap));
    }

    @Test
    void longestMatch_wins_evenAgainstBroaderDisallow() {
        var rules = List.of(
                RobotsEngine.compileRule(RobotsEngine.RuleType.DISALLOW, "/public"),
                RobotsEngine.compileRule(RobotsEngine.RuleType.ALLOW,    "/public/ok*")
        );
        var gmap = groupForUA("ua", rules);

        assertFalse(RobotsEngine.isAllowed("https://ex.com/public",           "ua", gmap));
        assertTrue (RobotsEngine.isAllowed("https://ex.com/public/ok",        "ua", gmap));
        assertTrue (RobotsEngine.isAllowed("https://ex.com/public/ok/deeper", "ua", gmap));
        assertFalse(RobotsEngine.isAllowed("https://ex.com/public/ng",        "ua", gmap));
    }

    @Test
    void tieBreak_allowBeatsDisallow_whenSameRank() {
        var rules = List.of(
                RobotsEngine.compileRule(RobotsEngine.RuleType.ALLOW,    "/pub"),
                RobotsEngine.compileRule(RobotsEngine.RuleType.DISALLOW, "/pub")
        );
        var gmap = groupForUA("ua", rules);

        assertTrue (RobotsEngine.isAllowed("https://ex.com/pub",     "ua", gmap));
        assertTrue (RobotsEngine.isAllowed("https://ex.com/pub/xxx", "ua", gmap));
    }

    @Test
    void wildcard_and_specificDisallow() {
        var rules = List.of(
                RobotsEngine.compileRule(RobotsEngine.RuleType.ALLOW,    "/pub*"),
                RobotsEngine.compileRule(RobotsEngine.RuleType.DISALLOW, "/public/secret")
        );
        var gmap = groupForUA("ua", rules);

        assertTrue (RobotsEngine.isAllowed("https://ex.com/pub/x",         "ua", gmap));
        assertFalse(RobotsEngine.isAllowed("https://ex.com/public/secret", "ua", gmap));
    }
}
