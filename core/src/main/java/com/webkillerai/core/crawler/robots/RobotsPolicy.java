package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * RobotsPolicy (Spec v0.2 드롭인)
 * - 기존 RobotsCache/Crawler가 기대하는 API 유지:
 *   • static RobotsPolicy parse(String robotsTxt, String userAgent)
 *   • static RobotsPolicy allowAll()
 *   • boolean allow(String path)   // 기존 호환
 *   • boolean allow(URI url)       // 풀 URL 판정(권장)
 *
 * 내부는 Parser/Engine/Matcher를 사용:
 * - Path 기준 매칭(쿼리/프래그먼트 무시), 퍼센트 인코딩 HEX 대문자화(디코드 X)
 * - 접두 + '*' + '$', 최장일치, 동률 시 Allow 우선
 * - UA 선택: 정확 일치(대소문자 무시) 없으면 '*' 그룹
 */
public final class RobotsPolicy {

    private static final String DEFAULT_UA = "WebKillerAI";

    private final Map<String, RobotsEngine.UaGroup> groupMap; // UA(소문자) → 그룹
    private final String uaLower; // 소문자 정규화된 UA
    private final boolean allowAll;

    private RobotsPolicy(Map<String, RobotsEngine.UaGroup> groupMap, String userAgent, boolean allowAll) {
        this.groupMap = (groupMap == null) ? Map.of() : groupMap;
        this.uaLower = (userAgent == null || userAgent.isBlank())
                ? DEFAULT_UA.toLowerCase(Locale.ROOT)
                : userAgent.toLowerCase(Locale.ROOT);
        this.allowAll = allowAll;
    }

    /** robots.txt 본문 파싱 → 엔진용 그룹맵 구성(UA 키를 소문자화) */
    public static RobotsPolicy parse(String robotsTxt, String userAgent) {
        if (robotsTxt == null) robotsTxt = "";
        RobotsParser.ParsedRobots parsed = RobotsParser.parse(robotsTxt);

        Map<String, RobotsEngine.UaGroup> raw = parsed.toEngineGroupMap(); // UA 키가 대소문자 섞일 수 있음
        Map<String, RobotsEngine.UaGroup> gmap = new LinkedHashMap<>();
        raw.forEach((ua, grp) -> gmap.put(
                (ua == null ? "" : ua.toLowerCase(Locale.ROOT)),
                grp
        ));

        return new RobotsPolicy(gmap, userAgent, false);
    }

    /** 실패/없음 시 전체 허용 정책 */
    public static RobotsPolicy allowAll() {
        return new RobotsPolicy(Map.of(), DEFAULT_UA, true);
    }

    /** 경로만으로 판정(호환용). path가 null/빈이면 "/"로 간주 */
    public boolean allow(String path) {
        if (allowAll) return true;
        String p = (path == null || path.isBlank()) ? "/" : path;
        return RobotsEngine.isAllowed(p, uaLower, groupMap);
    }

    /** 풀 URL로 판정(권장). 내부에서 path 정규화 후 매칭 */
    public boolean allow(URI url) {
        if (allowAll) return true;
        String path = RobotsMatcher.normalizePath(url); // rawPath + %HEX 대문자화
        return RobotsEngine.isAllowed(path, uaLower, groupMap);
    }
    
    public boolean isAllowAll() {
        return allowAll;
    }
}
