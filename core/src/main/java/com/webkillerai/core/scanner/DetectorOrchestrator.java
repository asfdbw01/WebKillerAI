
package com.webkillerai.core.scanner;

import com.webkillerai.core.config.FeatureMatrix;
import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.detectors.*;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import com.webkillerai.core.util.ParamDiscovery;
import com.webkillerai.core.util.RateLimiter;
import com.webkillerai.core.util.UrlParamUtil;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.*;

/** 모드별 FeatureMatrix를 따라 액티브 프로브를 수행하는 오케스트레이터 */
@Deprecated
public class DetectorOrchestrator {

    private static final double SIZE_DELTA_PCT = 0.25;
    private static final int    SIZE_DELTA_MIN = 256;

    private final ProbeEngine engine;
    private final ScanConfig cfg;
    private final RateLimiter rl; // null이면 미사용

    private final XssReflectedDetector xss    = new XssReflectedDetector();
    private final SqliErrorDetector    sqli   = new SqliErrorDetector();
    private final CorsMisconfigDetector cors  = new CorsMisconfigDetector();
    private final OpenRedirectDetector openrd = new OpenRedirectDetector();
    private final PathTraversalDetector lfi   = new PathTraversalDetector();
    private final SstiSimpleDetector   ssti   = new SstiSimpleDetector();
    private final MixedContentDetector mixed  = new MixedContentDetector();

    public DetectorOrchestrator(ScanConfig cfg, RateLimiter sharedLimiter) {
        this.cfg = Objects.requireNonNull(cfg, "cfg");
        this.engine = new ProbeEngine(cfg);
        this.rl = sharedLimiter;
    }
    public DetectorOrchestrator(ScanConfig cfg) { this(cfg, null); }

    public List<VulnResult> scan(URI url) {
        List<VulnResult> out = new ArrayList<>();

        // SAFE만 차단 (SAFE_PLUS, AGGRESSIVE_LITE 등은 FeatureMatrix로 세부 게이트)
        if (cfg.getMode() == Mode.SAFE) return out;

        Set<String> dedup = new HashSet<>();
        try {
            acquire();

            // 0) 루트 GET
            HttpResponse<String> base = engine.get(url, Map.of("Accept", "text/html,application/xhtml+xml"));
            String html = base.body() == null ? "" : base.body();

            // 1) 파라미터 후보 (힌트 pinning + 발견 + 상한)
            List<String> targets = pickTargets(url, html, cfg);

            // 2) 엔드포인트 수집(동일 호스트)
            LinkedHashSet<URI> endpoints = new LinkedHashSet<>();
            endpoints.add(url);
            try {
                Document d = Jsoup.parse(html, url.toString());
                for (Element a : d.select("a[href]")) addEndpoint(endpoints, url, a.attr("abs:href"));
                for (Element f : d.select("form[action]")) {
                    String m = f.attr("method");
                    if (m == null || m.isEmpty() || "get".equalsIgnoreCase(m)) addEndpoint(endpoints, url, f.attr("abs:action"));
                }
                for (Element l : d.select("link[href]")) addEndpoint(endpoints, url, l.attr("abs:href"));
            } catch (Exception ignore) {}

            // 엔드포인트 상한 (모드별)
            List<URI> epList = new ArrayList<>(endpoints);
            int epCap = Math.max(1, FeatureMatrix.endpointCap(cfg.getMode()));
            if (epCap > 0 && epList.size() > epCap) epList = epList.subList(0, epCap);

            // 3) 각 엔드포인트 처리
            for (URI ep : epList) {

                int baseLenForEp = 0;
                try {
                    acquire();
                    HttpResponse<String> epBase = engine.get(ep, Map.of("Accept", "text/html,application/xhtml+xml"));
                    String b = epBase.body();
                    baseLenForEp = (b == null ? 0 : b.length());
                } catch (Exception ignore) {}

                for (String p : targets) {

                    // [옵션] Anomaly: benign 주입 후 길이 변화 — FeatureMatrix로 제어
                    if (FeatureMatrix.anomalySizeDelta(cfg.getMode()) && baseLenForEp > 0) {
                        try {
                            URI probe = UrlParamUtil.withAddedParams(ep, Map.of(p, List.of("WKAI_SIZE_PROBE")));
                            acquire();
                            HttpResponse<String> pr = engine.get(probe, Map.of("Accept", "text/html,application/xhtml+xml"));
                            int len2 = (pr.body() == null ? 0 : pr.body().length());
                            int diff = Math.abs(len2 - baseLenForEp);

                            if (diff >= SIZE_DELTA_MIN) {
                                double pct = baseLenForEp == 0 ? 1.0 : (double) diff / (double) baseLenForEp;
                                if (pct >= SIZE_DELTA_PCT) {
                                    String req1 = ProbeEngine.requestLine("GET", ep);
                                    String req2 = ProbeEngine.requestLine("GET", probe);
                                    String ev = "baseline=" + baseLenForEp + ", injected=" + len2 +
                                            ", delta=" + diff + String.format(" (%.1f%%)", pct * 100.0) +
                                            "\n" + req1 + "\n" + req2;
                                    VulnResult vr = VulnResult.builder()
                                            .issueType(IssueType.ANOMALY_SIZE_DELTA)
                                            .severity(Severity.INFO)
                                            .url(probe)
                                            .description("Response size changed significantly after benign parameter injection ('" + p + "').")
                                            .requestLine(req2)
                                            .evidenceSnippet(ev)
                                            .evidence(ev)
                                            .build();
                                    add(out, dedup, vr, "delta", p);
                                }
                            }
                        } catch (Exception ignore) {}
                    }

                    // 주입형 디텍터 (모드별 게이트)
                    if (FeatureMatrix.activeXssReflected(cfg.getMode())) {
                        acquire(); xss.detect(engine, cfg, ep, p).ifPresent(v -> add(out, dedup, v, "xss",  p));
                    }
                    if (FeatureMatrix.activeSqli(cfg.getMode())) {
                        acquire(); sqli.detect(engine, cfg, ep, p).ifPresent(v -> add(out, dedup, v, "sqli", p));
                    }
                    if (FeatureMatrix.activePathTraversal(cfg.getMode())) {
                        acquire(); lfi.detect(engine,  cfg, ep, p).ifPresent(v -> add(out, dedup, v, "lfi",  p));
                    }
                    if (FeatureMatrix.activeSsti(cfg.getMode())) {
                        acquire(); ssti.detect(engine, cfg, ep, p).ifPresent(v -> add(out, dedup, v, "ssti", p));
                    }
                }

                // 비주입형 디텍터 (모드별 게이트)
                if (FeatureMatrix.activeCors(cfg.getMode())) {
                    acquire(); cors.detect(engine, cfg, ep).ifPresent(v -> add(out, dedup, v, "cors",  "-"));
                }
                if (FeatureMatrix.activeOpenRedirect(cfg.getMode())) {
                    acquire(); openrd.detect(engine, cfg, ep).ifPresent(v -> add(out, dedup, v, "redir", "-"));
                }
                if (FeatureMatrix.activeMixedContent(cfg.getMode())) {
                    acquire(); mixed.detect(engine, cfg, ep).ifPresent(v -> add(out, dedup, v, "mixed", "-"));
                }
            }

        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignore) { }
        return out;
    }

    // --- cap 이전에 sqli/xss top-hint를 pinning ---
    private static List<String> pickTargets(URI url, String html, ScanConfig cfg) {
        LinkedHashSet<String> discovered = new LinkedHashSet<>(ParamDiscovery.discoverParamNames(url, html));

        String topSqli = cfg.getSqliParamHints().isEmpty() ? "id" : cfg.getSqliParamHints().get(0);
        String topXss  = cfg.getXssParamHints().isEmpty()  ? "q"  : cfg.getXssParamHints().get(0);

        LinkedHashSet<String> merged = new LinkedHashSet<>();
        merged.add(topSqli);
        merged.add(topXss);
        merged.addAll(discovered);
        merged.addAll(cfg.getXssParamHints());
        merged.addAll(cfg.getSqliParamHints());

        // 모드 기본 상한과 cfg 값을 보수적으로 병합
        int byMode = Math.max(1, FeatureMatrix.maxParamsPerUrlDefault(cfg.getMode()));
        int byCfg  = Math.max(1, cfg.getMaxParamsPerUrl());
        int cap    = Math.min(byMode, byCfg);

        List<String> list = new ArrayList<>(merged);
        return list.size() <= cap ? list : list.subList(0, cap);
    }

    private void acquire() throws InterruptedException { if (rl != null) rl.acquire(); }

    private void add(List<VulnResult> out, Set<String> dedup, VulnResult v, String kind, String param) {
        String path = v.getUrl() != null ? v.getUrl().getPath() : "/";
        String key = kind + "|" + path + "|" + (param == null ? "-" : param);
        if (dedup.add(key)) out.add(v);
    }

    private void addEndpoint(Set<URI> endpoints, URI base, String abs) {
        if (abs == null || abs.isBlank()) return;
        try {
            URI u = URI.create(abs);
            if (Objects.equals(u.getAuthority(), base.getAuthority())) {
                endpoints.add(u);
            }
        } catch (Exception ignore) {}
    }
}
