package com.webkillerai.core.util;

import java.net.URI;
import java.util.List;
import java.util.regex.Pattern;

public final class UrlExclusion {
    private UrlExclusion(){}

    /**
     * patterns 지원:
     * <ul>
     *   <li>접두(prefix): {@code "/oauth2"} 또는 {@code "https://host/path"}</li>
     *   <li>glob: {@code '*'}, {@code '?'} 포함
     *       (예: {@code "*&#47;logout*"}, {@code "/admin/*"})
     *   </li>
     *   <li>정규식: {@code "re:"} 접두 (예: {@code re:\?.*token=.*})</li>
     * </ul>
     */
    public static boolean isExcluded(URI url, List<String> patterns){
        if (url == null || patterns == null || patterns.isEmpty()) return false;
        final String s = url.toString();
        for (String p : patterns) {
            if (p == null || p.isBlank()) continue;

            if (p.startsWith("re:")) {
                // 정규식
                String rx = p.substring(3);
                if (Pattern.compile(rx, Pattern.CASE_INSENSITIVE).matcher(s).find()) return true;

            } else if (p.indexOf('*') >= 0 || p.indexOf('?') >= 0) {
                // glob
                String rx = globToRegex(p);
                if (Pattern.compile(rx, Pattern.CASE_INSENSITIVE).matcher(s).find()) return true;

            } else {
                // prefix
                if (s.startsWith(p)) return true;

                // 호스트 상대 prefix: "/oauth2" 같은 경우
                if (p.startsWith("/") && s.contains("://")) {
                    int i = s.indexOf('/', s.indexOf("://") + 3);
                    String pathAndMore = (i > 0) ? s.substring(i) : "/";
                    if (pathAndMore.startsWith(p)) return true;
                }
            }
        }
        return false;
    }

    private static String globToRegex(String glob){
        StringBuilder r = new StringBuilder();
        // 대소문자 무시는 compile 시 CASE_INSENSITIVE 플래그로 처리
        for (int i = 0; i < glob.length(); i++){
            char c = glob.charAt(i);
            switch(c){
                case '*': r.append(".*"); break;
                case '?': r.append('.'); break;
                case '.': case '\\': case '+': case '(': case ')':
                case '^': case '$': case '|': case '{': case '}':
                case '[': case ']': r.append('\\').append(c); break;
                default: r.append(c);
            }
        }
        return r.toString();
    }
}
