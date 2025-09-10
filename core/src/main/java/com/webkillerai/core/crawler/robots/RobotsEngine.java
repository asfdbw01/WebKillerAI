package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WebKillerAI robots 엔진 (Mini Spec v0.2)
 * - Path만 매칭. 쿼리/프래그먼트 무시.
 * - 퍼센트 인코딩은 디코드하지 않음. HEX만 대문자화.
 * - 최장일치 우선, 길이 동률이면 Allow 우선.
 * - UA 그룹: 정확 일치 우선(맵 키), 없으면 '*' 그룹.
 * - 매칭은 반드시 RobotsMatcher.matches(...) 로 일원화한다.
 */
public final class RobotsEngine {

    public enum RuleType { ALLOW, DISALLOW }

    public static final class Rule {
        public final RuleType type;
        public final String rawPattern;   // 예: "/admin*", "/q", "/admin$"
        // regex는 더 이상 사용하지 않지만, 호환을 위해 필드만 유지(미사용).
        public final Pattern regex;
        public final int rank;            // 우선순위 계산용(스펙: '$' 제외 길이, '*'는 1자로)

        public Rule(RuleType type, String rawPattern, Pattern regex, int rank) {
            this.type = type;
            this.rawPattern = rawPattern;
            this.regex = regex;
            this.rank = rank;
        }
    }

    public static final class UaGroup {
        public final String name;         // 예: "mybot" 또는 "*"
        public final List<Rule> rules;

        public UaGroup(String name, List<Rule> rules) {
            this.name = name;
            this.rules = rules;
        }
    }

    private RobotsEngine() {}

    // ---------- 정규화 유틸 ----------
    private static final Pattern PERCENT_HEX = Pattern.compile("%([0-9a-fA-F]{2})");

    /** 퍼센트 HEX만 대문자화(디코딩하지 않음). */
    private static String uppercasePercentHex(String s) {
        if (s == null || s.isEmpty()) return s;
        StringBuffer sb = new StringBuffer();
        Matcher m = PERCENT_HEX.matcher(s);
        while (m.find()) {
            m.appendReplacement(sb, "%" + m.group(1).toUpperCase(Locale.ROOT));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** URL에서 raw path 추출 → 빈/null이면 "/" → 퍼센트 HEX만 대문자화. */
    public static String normalizePathFromUrl(String url) {
        URI u = URI.create(url);
        String p = u.getRawPath(); // path만
        if (p == null || p.isEmpty()) p = "/";
        return uppercasePercentHex(p);
    }

    /** 규칙 문자열(Allow/Disallow 값) 정규화: trim + 퍼센트 HEX 대문자화. */
    public static String normalizeRuleValue(String s) {
        if (s == null) return "";
        return uppercasePercentHex(s.trim());
    }

    // ---------- 규칙 컴파일 ----------
    /** 스펙 일치: 빈 Allow/Disallow는 규칙으로 취급하지 않음, rank는 effectiveLen 사용 */
    public static Rule compileRule(RuleType type, String value) {
        String v = normalizeRuleValue(value);
        if (v.isEmpty()) return null; // 빈 규칙은 무시(Allow/Disallow 공통)

        // 스펙: '$'는 길이에 미포함, '*'는 1자로 카운트 → effectiveLen 사용
        int rank = RobotsMatcher.effectiveLen(v);

        // 더 이상 엔진 자체 정규식에 의존하지 않음(매칭은 RobotsMatcher로 일원화)
        return new Rule(type, v, null, rank);
    }

    // ---------- UA 그룹 선택 ----------
    public static UaGroup selectGroup(Map<String, UaGroup> groups, String userAgent) {
        String ua = (userAgent == null) ? "" : userAgent;
        UaGroup exact = groups.get(ua);
        if (exact != null) return exact;
        UaGroup star = groups.get("*");
        if (star != null) return star;
        return new UaGroup("*", List.of()); // 규칙 없음
    }

    // ---------- 판정 ----------
    /** 규칙이 하나도 매치되지 않으면 허용. 최장일치 승리, 동률 시 Allow 우선. */
    public static boolean isAllowed(String url, String userAgent, Map<String, UaGroup> groups) {
        String path = normalizePathFromUrl(url);
        UaGroup g = selectGroup(groups, userAgent);

        Rule best = null;
        for (Rule r : g.rules) {
            if (r == null) continue;
            // ★ 단일 소스: 매칭은 반드시 RobotsMatcher.matches 사용
            if (!RobotsMatcher.matches(path, r.rawPattern)) continue;

            if (best == null) {
                best = r;
            } else if (r.rank > best.rank) {
                best = r; // 더 긴 일치 규칙 승리
            } else if (r.rank == best.rank) {
                if (r.type == RuleType.ALLOW && best.type == RuleType.DISALLOW) {
                    best = r; // 동률이면 Allow 우선
                }
            }
        }
        return (best == null) || best.type == RuleType.ALLOW;
    }
}
