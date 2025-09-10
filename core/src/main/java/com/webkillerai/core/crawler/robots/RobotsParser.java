package com.webkillerai.core.crawler.robots;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RobotsParser (Spec v0.2)
 * - 지원 지시어: User-agent / Allow / Disallow / Crawl-delay (키 대소문자 무시)
 * - 연속된 User-agent 라인은 "같은 그룹"으로 취급, 그 뒤 Allow/Disallow 누적
 * - UA 저장: 소문자
 * - UA 선택: UA 정확 일치(대소문자 무시), 없으면 "*" 그룹
 * - 규칙 값: 빈 값은 무시, 퍼센트 HEX 대문자 정규화만 수행(접두 의미로 '*' 추가 금지)
 */
public final class RobotsParser {

    private RobotsParser() {}

    private static final Pattern KV = Pattern.compile("^\\s*([A-Za-z-]+)\\s*:\\s*(.*?)\\s*$");
    private static final String UA_ALL = "*";
    private static final String DEFAULT_UA = "webkillerai";

    public static ParsedRobots parse(String robotsTxt) {
        if (robotsTxt == null) robotsTxt = "";

        // UA(소문자) → 규칙
        Map<String, RobotsRules> byUa = new LinkedHashMap<>();

        // 현재 UA 그룹(연속 User-agent 라인)
        List<String> currentAgents = new ArrayList<>();
        boolean lastWasUA = false;

        for (String rawLine : robotsTxt.split("\\r?\\n")) {
            String line = stripComment(rawLine).trim();
            if (line.isEmpty()) continue;

            Matcher m = KV.matcher(line);
            if (!m.matches()) continue;

            String key = m.group(1).toLowerCase(Locale.ROOT);
            String val = m.group(2).trim();

            switch (key) {
                case "user-agent" -> {
                    String ua = (val.isEmpty() ? UA_ALL : val).toLowerCase(Locale.ROOT);
                    if (!lastWasUA) {
                        // 새 그룹 시작
                        currentAgents = new ArrayList<>();
                    }
                    currentAgents.add(ua);
                    byUa.putIfAbsent(ua, new RobotsRules());
                    lastWasUA = true;
                }
                case "allow" -> {
                    ensureAgents(currentAgents, byUa);
                    if (!val.isEmpty()) {
                        String norm = RobotsMatcher.normalizeRule(val);
                        for (String ua : currentAgents) byUa.get(ua).addAllow(norm);
                    }
                    lastWasUA = false;
                }
                case "disallow" -> {
                    ensureAgents(currentAgents, byUa);
                    if (!val.isEmpty()) {
                        String norm = RobotsMatcher.normalizeRule(val);
                        for (String ua : currentAgents) byUa.get(ua).addDisallow(norm);
                    }
                    lastWasUA = false;
                }
                case "crawl-delay" -> {
                    // 현재는 무시(확장 여지)
                    lastWasUA = false;
                }
                default -> {
                    // 기타 지시어 무시
                    lastWasUA = false;
                }
            }
        }

        // 어떤 UA도 정의되지 않았다면 "*" 기본 그룹 생성
        byUa.putIfAbsent(UA_ALL, new RobotsRules());

        return new ParsedRobots(byUa);
    }

    private static void ensureAgents(List<String> currentAgents, Map<String, RobotsRules> byUa) {
        if (currentAgents.isEmpty()) {
            currentAgents.add(UA_ALL);
            byUa.putIfAbsent(UA_ALL, new RobotsRules());
        }
    }

    private static String stripComment(String s) {
        int i = s.indexOf('#');
        return i >= 0 ? s.substring(0, i) : s;
    }

    /** UA 선택 포함 결과 */
    public record ParsedRobots(Map<String, RobotsRules> byUa) {

        /** UA 정확 일치(대소문자 무시), 없으면 "*" 그룹 */
        public RobotsRules selectFor(String userAgent) {
            String uaLower = (userAgent == null || userAgent.isBlank())
                    ? DEFAULT_UA
                    : userAgent.toLowerCase(Locale.ROOT);
            RobotsRules exact = byUa.get(uaLower);
            if (exact != null) return exact;
            RobotsRules star = byUa.get(UA_ALL);
            return (star != null ? star : new RobotsRules());
        }

        /** 엔진용: 전체 그룹을 그대로(UA 소문자 키) 변환 */
        public Map<String, RobotsEngine.UaGroup> toEngineGroupMap() {
            Map<String, RobotsEngine.UaGroup> out = new LinkedHashMap<>();
            byUa.forEach((ua, rules) -> out.put(ua, rules.toEngineGroup(ua)));
            return out;
        }

        /** 선택된 그룹 + '*' 폴백만 제공하고 싶을 때(선택) */
        public Map<String, RobotsEngine.UaGroup> toSelectedGroupMap(String userAgent) {
            Map<String, RobotsEngine.UaGroup> out = new LinkedHashMap<>();
            String uaLower = (userAgent == null || userAgent.isBlank())
                    ? DEFAULT_UA
                    : userAgent.toLowerCase(Locale.ROOT);
            RobotsRules picked = selectFor(uaLower);
            out.put(uaLower, picked.toEngineGroup(uaLower));
            RobotsRules star = byUa().get(UA_ALL);
            if (star != null) out.put(UA_ALL, star.toEngineGroup(UA_ALL));
            return out;
        }
    }
}
