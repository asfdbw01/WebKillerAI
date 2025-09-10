package com.webkillerai.core.util;

import java.net.URI;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * URL 쿼리 파라미터 유틸 (Java 17)
 * - withParam: 기존에 같은 키가 있으면 건드리지 않음(append-only).
 * - withAddedParams: add의 키 중 기존에 "없는 키"만 추가(append-only, 다값 지원).
 * - withParamOverrideFirst: 주어진 키의 기존 값들을 제거하고 key=value를 쿼리 선두로 배치(프로브용 권장).
 * - pickParamKeys: 쿼리 키를 힌트 우선으로 정렬해 상위 max 반환(쿼리 없으면 힌트로 채움).
 * - normalize: host(lowercase) + path만 남김(쿼리/프래그먼트 제거) → 중복 억제 키에 사용.
 * - parseQuery: 단일값 맵(마지막 값을 채택). parseQueryMulti: 다값 맵.
 */
public final class UrlParamUtil {
    private UrlParamUtil() {}

    /** base에 key=value를 append-only로 추가. 이미 key가 존재하면 base 그대로 반환. */
    public static URI withParam(URI base, String key, String value) {
        Objects.requireNonNull(base, "base");
        if (key == null || key.isEmpty()) throw new IllegalArgumentException("key must not be empty");

        Map<String, List<String>> existing = parseQueryMulti(base);
        if (containsKeyIgnoreCase(existing.keySet(), key)) return base; // 이미 있으면 그대로

        String newQuery = buildQuery(merge(existing, Map.of(key, List.of(value == null ? "" : value))));
        return rebuild(base, newQuery);
    }

    /**
     * 기존 쿼리에 add를 append.
     * - append-only 정책: add 내 각 키가 기존에 "없을 때만" 추가(중복 키 방지).
     * - add의 값 리스트가 null/비어있으면 빈 값 1개로 취급(key=).
     * - 키 비교는 대소문자 무시.
     */
    public static URI withAddedParams(URI base, Map<String, List<String>> add) {
        Objects.requireNonNull(base, "base");
        if (add == null || add.isEmpty()) return base;

        Map<String, List<String>> existing = parseQueryMulti(base);
        Map<String, List<String>> toAppend = new LinkedHashMap<>();
        for (var e : add.entrySet()) {
            String k = e.getKey();
            if (k == null || k.isBlank()) continue;
            if (containsKeyIgnoreCase(existing.keySet(), k)) continue; // 기존 키 유지
            List<String> vals = e.getValue();
            if (vals == null || vals.isEmpty()) vals = List.of("");
            toAppend.put(k, vals);
        }
        if (toAppend.isEmpty()) return base;

        Map<String, List<String>> merged = new LinkedHashMap<>(existing);
        toAppend.forEach((k, v) -> merged.put(k, new ArrayList<>(v)));
        String newQuery = buildQuery(merged);
        return rebuild(base, newQuery);
    }

    /**
     * ★ 프로브/주입 권장 방식:
     *   1) 해당 key의 기존 항목을 모두 제거(대소문자 무시)하고
     *   2) enc(key)=enc(value) 쌍을 쿼리의 "선두"에 배치.
     * 서버가 "첫 번째 값"만 읽는 케이스를 안전하게 커버한다.
     */
    public static URI withParamOverrideFirst(URI base, String key, String value) {
        Objects.requireNonNull(base, "base");
        if (key == null || key.isBlank()) throw new IllegalArgumentException("key must not be blank");
        String raw = base.getRawQuery();

        List<String> preserved = new ArrayList<>();
        if (raw != null && !raw.isBlank()) {
            for (String part : raw.split("&")) {
                if (part.isBlank()) continue;
                int eq = part.indexOf('=');
                String kRaw = (eq >= 0 ? part.substring(0, eq) : part);
                String kDec = dec(kRaw);
                if (!kDec.equalsIgnoreCase(key)) {
                    preserved.add(part); // 원본 형식 그대로 보존
                }
            }
        }

        StringBuilder q = new StringBuilder();
        q.append(enc(key)).append('=').append(enc(value == null ? "" : value));
        for (String part : preserved) {
            q.append('&').append(part);
        }
        return rebuild(base, q.toString());
    }

    /** URL의 쿼리 키를 힌트 우선으로 정렬해 상위 max 반환. 쿼리 없으면 힌트로 채움. */
    public static List<String> pickParamKeys(URI url, List<String> hints, int max) {
        Objects.requireNonNull(url, "url");
        if (max <= 0) return Collections.emptyList();
        List<String> hintList = (hints == null) ? Collections.emptyList() : new ArrayList<>(hints);

        Map<String, List<String>> q = parseQueryMulti(url);
        List<String> keys = new ArrayList<>(q.keySet());

        if (keys.isEmpty()) {
            List<String> out = new ArrayList<>();
            for (String h : hintList) {
                if (h == null || h.isBlank()) continue;
                if (!out.contains(h)) out.add(h);
                if (out.size() >= max) break;
            }
            return out;
        }

        keys.sort((a, b) -> {
            int ia = indexOrMax(hintList, a);
            int ib = indexOrMax(hintList, b);
            if (ia != ib) return Integer.compare(ia, ib);
            return a.compareTo(b);
        });

        return (keys.size() > max) ? keys.subList(0, max) : keys;
    }

    /** host(lowercase) + path만 남김(쿼리/프래그먼트 제거). 중복 억제 키에 사용. */
    public static String normalize(URI url) {
        Objects.requireNonNull(url, "url");
        String host = Optional.ofNullable(url.getHost()).orElse("").toLowerCase(Locale.ROOT);
        String path = (url.getPath() == null || url.getPath().isEmpty()) ? "/" : url.getPath();
        return host + path;
    }

    /** 단일값 쿼리 파싱(마지막 값을 채택). 입력 순서 유지. */
    public static Map<String, String> parseQuery(URI url) {
        Map<String, List<String>> multi = parseQueryMulti(url);
        Map<String, String> single = new LinkedHashMap<>();
        for (var e : multi.entrySet()) {
            List<String> vals = e.getValue();
            single.put(e.getKey(), vals.isEmpty() ? "" : vals.get(vals.size() - 1));
        }
        return single;
    }

    /** 다값 쿼리 파싱. 입력 순서 유지. */
    public static Map<String, List<String>> parseQueryMulti(URI url) {
        Objects.requireNonNull(url, "url");
        Map<String, List<String>> m = new LinkedHashMap<>();
        String q = url.getRawQuery();
        if (q == null || q.isEmpty()) return m;

        for (String p : q.split("&")) {
            if (p.isEmpty()) continue;
            int i = p.indexOf('=');
            final String k, v;
            if (i < 0) {
                k = dec(p);
                v = "";
            } else {
                k = dec(p.substring(0, i));
                v = dec(p.substring(i + 1));
            }
            m.computeIfAbsent(k, __ -> new ArrayList<>()).add(v);
        }
        return m;
    }

    // ---------- helpers ----------
    private static String buildQuery(Map<String, List<String>> params) {
        if (params.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (var e : params.entrySet()) {
            String k = e.getKey();
            if (k == null) continue;
            List<String> vals = e.getValue();
            if (vals == null || vals.isEmpty()) vals = List.of("");
            for (String v : vals) {
                if (!first) sb.append('&');
                sb.append(enc(k)).append('=').append(enc(v == null ? "" : v));
                first = false;
            }
        }
        return sb.toString();
    }

    private static Map<String, List<String>> merge(Map<String, List<String>> a, Map<String, List<String>> b) {
        Map<String, List<String>> out = new LinkedHashMap<>(a);
        for (var e : b.entrySet()) {
            out.computeIfAbsent(e.getKey(), __ -> new ArrayList<>()).addAll(e.getValue());
        }
        return out;
    }

    private static boolean containsKeyIgnoreCase(Collection<String> keys, String key) {
        for (String k : keys) {
            if (k != null && k.equalsIgnoreCase(key)) return true;
        }
        return false;
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
    private static String dec(String s) { return URLDecoder.decode(s, StandardCharsets.UTF_8); }

    /** 안전한 URI 재조립(문자열 이어붙이기 지양). */
    private static URI rebuild(URI base, String newQuery) {
        try {
            return new URI(
                base.getScheme(),
                base.getUserInfo(),
                base.getHost(),
                base.getPort(),
                (base.getPath() == null || base.getPath().isEmpty()) ? "/" : base.getPath(),
                (newQuery == null || newQuery.isEmpty()) ? null : newQuery,
                base.getFragment()
            );
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to rebuild URI", e);
        }
    }

    private static int indexOrMax(List<String> list, String key) {
        int idx = list.indexOf(key);
        return (idx < 0) ? Integer.MAX_VALUE : idx;
    }
}
