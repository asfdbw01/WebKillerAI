package com.webkillerai.core.util;

import java.net.URI;
import java.net.URISyntaxException;

/** URL 정규화 + same-domain 판정 유틸 */
public final class UrlUtils {
    private UrlUtils(){}

    /**
     * 정규화 규칙:
     * - fragment 제거(#... 제거)
     * - host 소문자
     * - 기본 포트 제거(http:80, https:443)
     * - 빈/누락 경로를 "/"로, 중복 슬래시 축소
     */
    public static URI normalize(URI u) {
        if (u == null) return null;

        String scheme = (u.getScheme() == null ? "http" : u.getScheme()).toLowerCase();
        String host = u.getHost() != null ? u.getHost() : u.getAuthority();
        if (host == null) host = "";
        host = host.toLowerCase();

        int port = u.getPort();
        if ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443)) {
            port = -1; // 기본 포트 제거
        }

        String path = (u.getPath() == null || u.getPath().isEmpty()) ? "/" : u.getPath();
        // 중복 슬래시 축소(쿼리/프로토콜 부분은 변경하지 않음)
        path = path.replaceAll("/{2,}", "/");

        String query = u.getQuery();

        try {
            return new URI(scheme, null, host, port, path, query, null); // fragment 제거
        } catch (URISyntaxException e) {
            // 파싱 실패 시 원본 유지(보수적)
            return u;
        }
    }

    /** host 기준 동일 도메인 판정(소문자 비교) */
    public static boolean sameDomain(URI a, URI b) {
        if (a == null || b == null) return false;
        String ha = a.getHost() == null ? "" : a.getHost().toLowerCase();
        String hb = b.getHost() == null ? "" : b.getHost().toLowerCase();
        return ha.equals(hb);
    }
}
