package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 경로 기준 매칭:
 * - 쿼리 무시, 프래그먼트 제거(URI.getRawPath 사용)
 * - 퍼센트 인코딩 HEX 대문자 통일(디코드하지 않음)
 * 우선순위:
 *  (1) 더 긴 규칙 문자열이 승 (단, '*'는 길이에 미산입, 끝의 '$'도 미산입)
 *  (2) 길이 같으면 Allow 우선
 * 패턴:
 *  - '*' 임의 길이
 *  - 끝의 '$' 는 경로 끝 고정(정확 일치)
 *  - 기본은 접두(prefix) 매칭이되, 세그먼트 경계까지(뒤가 끝이거나 '/')
 */
public final class RobotsMatcher {
    private RobotsMatcher() {}

    public static boolean isAllowed(URI url, RobotsRules rules) {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(rules, "rules");

        String path = normalizePath(url);
        Decision best = null;

        // 규칙도 퍼센트 인코딩 HEX 대문자 정규화
        for (String p : rules.disallow) {
            String pr = normalizeRule(p);
            if (matches(path, pr)) best = pickBetter(best, new Decision(false, pr));
        }
        for (String p : rules.allow) {
            String pr = normalizeRule(p);
            if (matches(path, pr)) best = pickBetter(best, new Decision(true, pr));
        }
        // 규칙 매칭 없으면 허용
        return best == null || best.allow;
    }

    /** 룰 문자열 정규화(퍼센트 인코딩 HEX 대문자). '$'는 보존 */
    static String normalizeRule(String rule) {
        if (rule == null) return "";
        String r = rule.trim();
        if (r.isEmpty()) return r;
        boolean endsWithDollar = r.endsWith("$");
        if (endsWithDollar) r = r.substring(0, r.length() - 1);
        r = uppercasePctHex(r);
        return endsWithDollar ? (r + "$") : r;
    }

    // 규칙 선택: 더 긴 규칙 우선( '*'는 길이에 미산입, '$'는 미산입 ), 같으면 Allow 우선
    static Decision pickBetter(Decision a, Decision b) {
        if (a == null) return b;
        int la = effectiveLen(a.raw), lb = effectiveLen(b.raw);
        if (lb > la) return b;
        if (lb < la) return a;
        if (b.allow && !a.allow) return b; // 동일 길이 → Allow 우선
        return a;
    }

    static boolean matches(String path, String rule) {
        if (rule == null) return false;
        String r = rule.trim();
        if (r.isEmpty()) return false;

        boolean endsWithDollar = r.endsWith("$");
        if (endsWithDollar) r = r.substring(0, r.length() - 1);

        // 와일드카드가 있으면 정규식으로 처리
        if (r.indexOf('*') >= 0) {
            String regex = "^" + toRegexKeepingStar(r) + (endsWithDollar ? "$" : ".*");
            return Pattern.compile(regex).matcher(path).matches();
        }

        // ★ 평문 규칙:
        //   - '$'가 있으면 정확히 일치
        //   - 없고 r이 '/'로 끝나면 디렉터리 접두 → 하위 전부 매치
        //   - 그 외에는 "세그먼트 경계" 접두: path가 r로 시작하고, 바로 뒤가 끝이거나 '/'
        if (endsWithDollar) {
            return path.equals(r);
        }
        if (r.endsWith("/")) {
            return path.startsWith(r); // 디렉터리 프리픽스: 하위 모두
        }
        if (!path.startsWith(r)) return false;
        if (path.length() == r.length()) return true;       // 정확히 r로 끝
        char next = path.charAt(r.length());
        return next == '/'; // 세그먼트 경계
    }

    static String toRegexKeepingStar(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '*') sb.append(".*");
            else sb.append(Pattern.quote(String.valueOf(c)));
        }
        return sb.toString();
    }

    /** URL 경로 정규화: rawPath 사용 + 퍼센트 HEX 대문자화 */
    static String normalizePath(URI uri) {
        String rawPath = uri.getRawPath(); // 디코딩하지 않은 원본 경로
        if (rawPath == null || rawPath.isEmpty()) rawPath = "/";
        return uppercasePctHex(rawPath);
    }

    /** 퍼센트 인코딩을 대문자 HEX로 통일 */
    static String uppercasePctHex(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '%' && i + 2 < s.length()) {
                char a = s.charAt(i + 1), b = s.charAt(i + 2);
                if (isHex(a) && isHex(b)) {
                    out.append('%')
                       .append(Character.toUpperCase(a))
                       .append(Character.toUpperCase(b));
                    i += 2; // 두 글자 소비
                    continue;
                }
            }
            out.append(ch);
        }
        return out.toString();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }

    static final class Decision {
        final boolean allow;
        final String raw;
        Decision(boolean allow, String raw) { this.allow = allow; this.raw = raw; }
    }

    /** 우선순위 길이: 끝의 '$' 제외, '*'는 0 길이로 간주(구체성 낮음) */
    static int effectiveLen(String raw) {
        if (raw == null) return 0;
        String r = raw.trim();
        int end = r.endsWith("$") ? r.length() - 1 : r.length();
        int score = 0;
        for (int i = 0; i < end; i++) {
            char c = r.charAt(i);
            if (c == '*') continue; // 와일드카드는 특이도에 반영하지 않음
            score++;
        }
        return score;
    }
}
