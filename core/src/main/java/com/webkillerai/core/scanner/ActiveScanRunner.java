// core/src/main/java/com/webkillerai/core/scanner/ActiveScanRunner.java
package com.webkillerai.core.scanner;

import com.webkillerai.core.config.FeatureMatrix;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.detectors.OpenRedirectDetector;  // fallback
import com.webkillerai.core.scanner.probe.ProbeEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 액티브 스캔 실행기:
 * - URL/모드에 맞는 "프로브 계획"을 만들고 ProbeEngine에 위임해 실행한다.
 * - ProbeEngine의 실행 메서드 이름/시그니처 차이를 감안해
 *   executePlanned / execute / run 중 존재하는 메서드를 리플렉션으로 호출한다.
 *
 * 비파괴 원칙: GET/HEAD/OPTIONS 범위, 바디 주입 금지(쿼리/헤더만).
 */
public final class ActiveScanRunner {

    private static final Logger LOG = LoggerFactory.getLogger(ActiveScanRunner.class);

    private final ProbeEngine engine;

    public ActiveScanRunner(ProbeEngine engine) {
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    /** 한 건의 프로브 계획(파라미터/헤더/페이지 단위) */
    public static final class ProbePlan {
        public final String issueKey;   // 예: "XSS_REFLECTED", "SQLI_ERROR", "OPEN_REDIRECT" ...
        public final String paramKey;   // 파라미터 키 또는 "-"(없음)
        public final String payload;    // 주입 값 or 헤더 라인 표현("Origin: https://evil.example")
        public final String payloadSig; // 디듀프용 시그니처 키
        public final Kind kind;         // PARAM, HEADER, PAGE

        public enum Kind { PARAM, HEADER, PAGE }

        public ProbePlan(String issueKey, String paramKey, String payload, String payloadSig, Kind kind) {
            this.issueKey = issueKey;
            this.paramKey = (paramKey == null || paramKey.isBlank()) ? "-" : paramKey;
            this.payload = payload;
            this.payloadSig = (payloadSig == null ? "" : payloadSig);
            this.kind = Objects.requireNonNull(kind, "kind");
        }

        @Override public String toString() {
            return "ProbePlan{" + issueKey + " param=" + paramKey + " kind=" + kind + " sig=" + payloadSig + "}";
        }
    }

    /** ScanService에서 호출하는 단일 엔트리 */
    public List<VulnResult> run(ScanConfig cfg, URI url) {
        try {
            final Mode mode = cfg.getMode();
            if (!FeatureMatrix.isAnyActive(mode)) return List.of();

            // 1) 계획 수립 (cfg 포함으로 변경)
            List<ProbePlan> plans = buildPlans(cfg, url);
            if (plans.isEmpty()) return List.of();

            // 2) 디듀프
            plans = dedupe(url, plans);

            // 3) ProbeEngine 위임
            List<VulnResult> results = executeByReflection(cfg, url, plans);

            // 4) 🔴 Open Redirect 세이프티 넷 (엔진 미연결/미구현 대비)
            if (FeatureMatrix.activeOpenRedirect(mode)
                    && hasOpenRedirectPlan(plans)
                    && !containsOpenRedirect(results)) {
                try {
                    var or = new OpenRedirectDetector().detect(this.engine, cfg, url);
                    or.ifPresent(results::add);
                } catch (Throwable t) {
                    LOG.debug("OpenRedirect fallback failed: {}", t.toString());
                }
            }

            return results;

        } catch (Throwable t) {
            LOG.warn("ActiveScanRunner.run failed: {}", t.toString());
            return List.of();
        }
    }

    /* ===============================
       계획 수립 (모드별 프로브 셋)
       =============================== */

    private List<ProbePlan> buildPlans(ScanConfig cfg, URI url) {
        final Mode mode = cfg.getMode();
        List<ProbePlan> out = new ArrayList<>();

        // ── 0) 모드 플래그 일괄 평가 (단일 진실원: FeatureMatrix)
        final boolean xss   = FeatureMatrix.activeXssReflected(mode);
        final boolean sqli  = FeatureMatrix.activeSqli(mode);
        final boolean cors  = FeatureMatrix.activeCors(mode);
        final boolean orOn  = FeatureMatrix.activeOpenRedirect(mode);
        final boolean lfi   = FeatureMatrix.activePathTraversal(mode);
        final boolean ssti  = FeatureMatrix.activeSsti(mode);
        final boolean mixed = FeatureMatrix.activeMixedContent(mode);

        // (임시 디버그) 무엇이 켜졌는지 한 눈에 — 원인 추적 끝나면 DEBUG 유지/하향
        LOG.info("active-flags mode={} xss={} sqli={} cors={} or={} lfi={} ssti={} mixed={}",
                mode, xss, sqli, cors, orOn, lfi, ssti, mixed);

        // ── 1) 쿼리 파라미터 후보 선정
        List<String> allKeys = extractParamKeys(url);
        int limit = Math.max(1, FeatureMatrix.maxParamsPerUrlDefault(mode));
        List<String> keys = chooseParamKeys(allKeys, limit);
        boolean hasQuery = (keys != null && !keys.isEmpty());

        // ── 2) OR 후보(리다이렉트 유사 키) 추림
        List<String> orCandidates = new ArrayList<>();
        for (String k : keys) if (isRedirectLike(k)) orCandidates.add(k);

        // ── 3) OR-only 빠른 길: 진짜 OR만 켠 프로필에서만 적용
        boolean orOnlyProfile = orOn && !(xss || sqli || cors || lfi || ssti || mixed);
        if (orOnlyProfile && orCandidates.isEmpty()) {
            LOG.debug("Skip ActiveRunner (OR-only fast path): no OR-like params on {}", url);
            return Collections.emptyList();
        }

        // ── 4) onQueryOnly 게이트: 파라미터 '필요' 디텍터(XSS/SQLi/LFI/SSTI)에만 적용
        boolean onQueryOnly = getActiveOnQueryOnly(mode, cfg);
        boolean blockParamRequired = onQueryOnly && !hasQuery;
        if (blockParamRequired) {
            LOG.debug("Param-required detectors gated by onQueryOnly=true (no query): {}", url);
        }

        // ── 5) 파라미터 '불필요' 디텍터: OR / CORS / Mixed
        if (orOn) {
            String orPayload = "https://wkai.example/";
            if (!orCandidates.isEmpty()) {
                for (String k : orCandidates) {
                    out.add(new ProbePlan("OPEN_REDIRECT", k, orPayload, "host_ext", ProbePlan.Kind.PARAM));
                }
            } else {
                // 폴백 1회(Page 힌트)
                out.add(new ProbePlan("OPEN_REDIRECT", "-", orPayload, "host_ext_page_hint", ProbePlan.Kind.PAGE));
            }
        }

        if (cors) {
            out.add(new ProbePlan("CORS_MISCONFIG", "-", "Origin:https://evil.example", "origin_host", ProbePlan.Kind.HEADER));
            out.add(new ProbePlan("CORS_MISCONFIG", "-", "Origin:null", "origin_null", ProbePlan.Kind.HEADER));
            out.add(new ProbePlan("CORS_MISCONFIG", "-", "Origin:https://sub.evil.example", "origin_sub", ProbePlan.Kind.HEADER));
        }

        if (mixed && isHttps(url)) {
            out.add(new ProbePlan("MIXED_CONTENT", "-", "", "scan_https_asset", ProbePlan.Kind.PAGE));
        }

        // ── 6) 파라미터 '필요' 디텍터: XSS / SQLi / LFI / SSTI
        if (!blockParamRequired) {
            if (xss)  {
                String xss1 = "WKAI</div><svg/onload=confirm(1)>";
                for (String k : prioritizeXssKeys(keys)) {
                    out.add(new ProbePlan("XSS_REFLECTED", k, xss1, "xss_polyglot_v1", ProbePlan.Kind.PARAM));
                }
            }
            if (sqli) {
                String sqli1 = "'";
                for (String k : prioritizeSqliKeys(keys)) {
                    out.add(new ProbePlan("SQLI_ERROR", k, sqli1, "tick_only", ProbePlan.Kind.PARAM));
                }
            }
            if (lfi)  {
                for (String k : prioritizeFileKeys(keys)) {
                    out.add(new ProbePlan("PATH_TRAVERSAL", k, "../../../../../etc/passwd", "unix_passwd", ProbePlan.Kind.PARAM));
                    out.add(new ProbePlan("PATH_TRAVERSAL", k, "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "unix_passwd_enc", ProbePlan.Kind.PARAM));
                }
            }
            if (ssti) {
                for (String k : keys) {
                    out.add(new ProbePlan("SSTI_PATTERN", k, "{{7*7}}WKAI", "jinja_expr_v1", ProbePlan.Kind.PARAM));
                }
            }
        }

        // ── 7) (옵션) AGGRESSIVE 추가 페이로드 훅 — 안전 가드 뒤에서만
        if (mode == Mode.AGGRESSIVE && sysBool("wk.aggressive.extra", false)) {
            for (String k : prioritizeFileKeys(keys)) {
                out.add(new ProbePlan("PATH_TRAVERSAL", k, "..%2F..%2Fwindows%2Fwin.ini", "win_ini_enc", ProbePlan.Kind.PARAM));
            }
            for (String k : keys) {
                out.add(new ProbePlan("SQLI_ERROR", k, "'\")--", "tick_quote_comment", ProbePlan.Kind.PARAM));
            }
        }

        LOG.debug("Active plans built: {} for {}", out.size(), url);
        return out;
    }

    /* ===============================
       실행 브리지 (ProbeEngine 위임)
       =============================== */

    @SuppressWarnings("unchecked")
    private List<VulnResult> executeByReflection(ScanConfig cfg, URI url, List<ProbePlan> plans) {
        try {
            Class<?> clazz = engine.getClass();
            Method m = findMethod(clazz, "executePlanned", ScanConfig.class, URI.class, List.class);
            if (m == null) m = findMethod(clazz, "execute",       ScanConfig.class, URI.class, List.class);
            if (m == null) m = findMethod(clazz, "run",           ScanConfig.class, URI.class, List.class);

            if (m != null) {
                Object ret = m.invoke(engine, cfg, url, plans);
                if (ret instanceof List<?> l) {
                    if (l.isEmpty() || l.get(0) instanceof VulnResult) {
                        return (List<VulnResult>) l;
                    }
                }
            } else {
                LOG.debug("No suitable ProbeEngine method found (executePlanned/execute/run). Returning empty.");
            }
        } catch (Throwable t) {
            LOG.warn("ProbeEngine delegation failed: {}", t.toString());
        }
        return new ArrayList<>();
    }

    private Method findMethod(Class<?> c, String name, Class<?>... sig) {
        try {
            return c.getMethod(name, sig);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    /* ===============================
       헬퍼들 (파라미터/휴리스틱/디듀프)
       =============================== */

    private static boolean isHttps(URI u) {
        String s = (u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT));
        return "https".equals(s);
    }

    /** 쿼리 파라미터 키 추출(UTF-8 디코드, 중복 제거, 최대 32개) */
    private List<String> extractParamKeys(URI url) {
        String q = url.getQuery();
        if (q == null || q.isBlank()) return List.of();
        List<String> keys = new ArrayList<>();
        for (String pair : q.split("&")) {
            if (pair.isEmpty()) continue;
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            if (!key.isEmpty()) keys.add(key);
            if (keys.size() >= 32) break;
        }
        // 중복 제거 + 순서 보존
        return new ArrayList<>(new LinkedHashSet<>(keys));
    }

    private List<String> chooseParamKeys(List<String> all, int limit) {
        if (all == null || all.isEmpty()) return List.of();
        List<String> sorted = new ArrayList<>(new LinkedHashSet<>(all)); // 순서 유지 + 중복 제거
        sorted.sort(Comparator.comparingInt(ActiveScanRunner::weightParam).reversed());
        int n = Math.min(sorted.size(), Math.max(1, limit));
        return sorted.subList(0, n);
    }

    private static int weightParam(String k) {
        String s = k.toLowerCase(Locale.ROOT);
        if (s.matches("^(id|q|query|search|redirect|returnurl|url|next|file|path)$")) return 100;
        if (s.contains("id") || s.contains("url") || s.contains("file")) return 60;
        return 10;
    }

    private static boolean isRedirectLike(String k) {
        String s = k.toLowerCase(Locale.ROOT);
        return s.contains("redirect") || s.contains("returnurl") || s.equals("url") || s.equals("next");
    }

    private static boolean isFileLike(String k) {
        String s = k.toLowerCase(Locale.ROOT);
        return s.contains("file") || s.contains("path");
    }

    private static List<String> prioritizeXssKeys(List<String> keys) {
        if (keys == null) return List.of();
        List<String> xs = new ArrayList<>(keys);
        xs.sort((a,b) -> Integer.compare(scoreXss(b), scoreXss(a)));
        return xs;
    }
    private static int scoreXss(String k) {
        String s = k.toLowerCase(Locale.ROOT);
        if (s.matches("^(q|query|search|s|keyword)$")) return 100;
        if (s.contains("q") || s.contains("search"))   return 60;
        return 10;
    }

    private static List<String> prioritizeSqliKeys(List<String> keys) {
        if (keys == null) return List.of();
        List<String> xs = new ArrayList<>(keys);
        xs.sort((a,b) -> Integer.compare(scoreSqli(b), scoreSqli(a)));
        return xs;
    }
    private static int scoreSqli(String k) {
        String s = k.toLowerCase(Locale.ROOT);
        if (s.matches("^(id|uid|user|no|prod|cat|page)$")) return 100;
        if (s.contains("id") || s.contains("user"))        return 60;
        return 10;
    }

    private static List<String> prioritizeFileKeys(List<String> keys) {
        if (keys == null) return List.of();
        List<String> xs = new ArrayList<>();
        for (String k : keys) if (isFileLike(k)) xs.add(k);
        if (xs.isEmpty()) xs = new ArrayList<>(keys);
        xs.sort((a,b) -> Integer.compare(scoreFile(b), scoreFile(a)));
        return xs;
    }
    private static int scoreFile(String k) {
        String s = k.toLowerCase(Locale.ROOT);
        if (s.matches("^(file|path)$")) return 100;
        if (s.contains("file") || s.contains("path")) return 60;
        return 10;
    }

    private List<ProbePlan> dedupe(URI url, List<ProbePlan> in) {
        Map<String, ProbePlan> m = new LinkedHashMap<>();
        String base = nullSafe(url.toString());
        for (ProbePlan p : in) {
            String key = String.join("|",
                    base,
                    nullSafe(p.paramKey),
                    nullSafe(p.issueKey),
                    nullSafe(p.payloadSig));
            m.putIfAbsent(key, p);
        }
        return new ArrayList<>(m.values());
    }

    private static String nullSafe(String s) { return (s == null ? "" : s); }

    /* ===============================
       설정/게이트 유틸
       =============================== */

    /** onQueryOnly: 프로필별 오버라이드 > 글로벌 > 기본값(SAFE_PLUS=true, 그 외=false) */
    private static boolean getActiveOnQueryOnly(Mode mode, ScanConfig cfg) {
        // 1) 프로필별 시스템 프로퍼티 우선
        String key = switch (mode) {
            case SAFE_PLUS -> "wk.safeplus.activeOnQueryOnly";
            case AGGRESSIVE_LITE -> "wk.agglite.activeOnQueryOnly";
            case AGGRESSIVE -> "wk.aggressive.activeOnQueryOnly";
            default -> null;
        };
        if (key != null) {
            String v = System.getProperty(key);
            if (v != null) return isTruthy(v);
        }
        // 2) 글로벌 시스템 프로퍼티
        String g = System.getProperty("wk.active.onQueryOnly");
        if (g != null) return isTruthy(g);

        // 3) ScanConfig 제공 시 우선(있으면)
        try {
            Method m = cfg.getClass().getMethod("isActiveOnQueryOnly");
            Object v = m.invoke(cfg);
            if (v instanceof Boolean b) return b;
        } catch (Throwable ignored) { /* no-op */ }

        // 4) 기본값
        return (mode == Mode.SAFE_PLUS);
    }

    private static boolean sysBool(String key, boolean def) {
        String v = System.getProperty(key);
        return v == null ? def : isTruthy(v);
    }

    private static boolean isTruthy(String v) {
        return "true".equalsIgnoreCase(v) || "1".equals(v) || "on".equalsIgnoreCase(v) || "yes".equalsIgnoreCase(v);
    }

    /* ===============================
       OR fallback 보조
       =============================== */

    private static boolean hasOpenRedirectPlan(List<ProbePlan> plans) {
        for (ProbePlan p : plans) {
            if ("OPEN_REDIRECT".equalsIgnoreCase(p.issueKey)) return true;
        }
        return false;
    }

    private static boolean containsOpenRedirect(List<VulnResult> results) {
        if (results == null || results.isEmpty()) return false;
        for (VulnResult vr : results) {
            try {
                try {
                    Method m = vr.getClass().getMethod("getTypeKey");
                    Object v = m.invoke(vr);
                    if (v != null && v.toString().toUpperCase(Locale.ROOT).contains("OPEN_REDIRECT")) return true;
                } catch (NoSuchMethodException ignored) { /* continue */ }

                try {
                    Method m = vr.getClass().getMethod("getType");
                    Object v = m.invoke(vr);
                    if (v != null && v.toString().toUpperCase(Locale.ROOT).contains("OPEN_REDIRECT")) return true;
                } catch (NoSuchMethodException ignored) { /* continue */ }

                if (vr.toString().toUpperCase(Locale.ROOT).contains("OPEN_REDIRECT")) return true;
            } catch (Throwable ignored) {
                // 체크 실패는 false로 취급
            }
        }
        return false;
    }
}
