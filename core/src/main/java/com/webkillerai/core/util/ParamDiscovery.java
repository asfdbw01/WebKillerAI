package com.webkillerai.core.util;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HTML/URL에서 주입 후보 파라미터명을 발견(Discover)하는 유틸.
 * - <a href>, <link href>의 쿼리 키
 * - <form> (GET 또는 method 미지정) 내 input/select/textarea/button[name]
 * - data-* 속성에서 키 추정 (data-user -> user)
 * - <script> 인라인 코드의 '?k=' 패턴, 외부 <script src>의 쿼리 키
 * - 현재 URL 자체의 쿼리 키
 * 반환 순서: 발견 우선순위 + 중복 제거(LinkedHashSet)
 */
public final class ParamDiscovery {
    private ParamDiscovery(){}

    // URL/스크립트에서 '?k=' 패턴을 찾기 위한 가벼운 정규식
    private static final Pattern QMARK_PARAM = Pattern.compile("[?&]([a-zA-Z0-9_\\-]{1,32})=");

    // 흔한 노이즈 키(트래킹/세션 등)
    private static final Set<String> NOISE = Set.of(
            "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
            "gclid","fbclid","yclid","mc_eid","ref","ref_src","ref_url",
            "jsessionid","phpsessid","sessionid","sid","cid","_ga","_gid"
    );

    /** HTML에서 GET 주입에 쓸 파라미터 후보명을 우선순위로 수집 */
    public static List<String> discoverParamNames(URI base, String html) {
        LinkedHashSet<String> out = new LinkedHashSet<>();

        // (0) 방어코드
        if (base == null) base = URI.create("http://localhost/");
        if (html == null) html = "";

        try {
            Document d = Jsoup.parse(html, base.toString());

            // (1) <a href="?k=v">
            d.select("a[href]").forEach(a -> addFromUrl(out, a.attr("abs:href")));

            // (1-추가) <link href="?k=v"> (canonical/next/prev 등)
            d.select("link[href]").forEach(l -> addFromUrl(out, l.attr("abs:href")));

            // (2) GET form + method 미지정 form 의 input/select/textarea/button[name]
            for (Element f : d.select("form[method=GET], form[method=get], form:not([method])")) {
                for (Element in : f.select("input[name], select[name], textarea[name], button[name]")) {
                    add(out, in.attr("name"));
                }
            }

            // (3) data-* 속성에서 키 추정 (data-user → user)
            d.getAllElements().forEach(e ->
                e.attributes().forEach(attr -> {
                    String k = attr.getKey();
                    if (k.startsWith("data-") && k.length() > 5 && k.length() <= 29) {
                        add(out, k.substring(5));
                    }
                })
            );

            // (4) <script> 인라인 내 간단 패턴 '?k=' (과탐 방지를 위해 태그당 8개 제한)
            for (Element s : d.select("script")) {
                Matcher m = QMARK_PARAM.matcher(s.data());
                int c = 0; while (m.find() && c++ < 8) add(out, m.group(1));
            }

            // (4-추가) 외부 스크립트 src의 쿼리에서도 키 수집
            d.select("script[src]").forEach(sc -> addFromUrl(out, sc.attr("abs:src")));

        } catch (Exception ignore) {
            // HTML 파싱 실패해도 아래 URL 기반 수집은 계속
        }

        // (5) 현재 URL 자체의 쿼리 키
        addFromUrl(out, base.toString());

        // (6) 노이즈 키 제거 (대소문자 무시)
        out.removeIf(k -> NOISE.contains(k.toLowerCase(Locale.ROOT)));

        return new ArrayList<>(out);
    }

    /** URL 문자열에서 '?k=' 패턴 추출 (최대 12개) */
    private static void addFromUrl(Set<String> out, String url) {
        if (url == null) return;
        Matcher m = QMARK_PARAM.matcher(url);
        int c = 0; while (m.find() && c++ < 12) add(out, m.group(1));
    }

    /** 키 유효성 검사 + 정규화 후 추가 */
    private static void add(Set<String> out, String k) {
        if (k == null) return;
        k = k.trim();
        if (k.isEmpty() || k.length() > 32) return;
        // 허용 문자: 영숫자/언더스코어/하이픈
        for (int i = 0; i < k.length(); i++) {
            char ch = k.charAt(i);
            if (!(Character.isLetterOrDigit(ch) || ch == '_' || ch == '-')) return;
        }
        out.add(k);
    }
}
