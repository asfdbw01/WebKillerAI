// core/src/main/java/com/webkillerai/core/service/ScanService.java
package com.webkillerai.core.service;

import com.webkillerai.core.api.ICrawler;
import com.webkillerai.core.api.IHttpAnalyzer;
import com.webkillerai.core.api.IScanner;
import com.webkillerai.core.crawler.Crawler;
import com.webkillerai.core.http.CountingRetryPolicy;
import com.webkillerai.core.http.DefaultRetryPolicy;
import com.webkillerai.core.http.HttpAnalyzer;
import com.webkillerai.core.model.HttpResponseData;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.ScanStats;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.SignatureScanner;
import com.webkillerai.core.scanner.ActiveScanRunner;            // ← 유지
import com.webkillerai.core.scanner.probe.ProbeEngine;          // ← 유지
import com.webkillerai.core.util.DefaultSleeper;
import com.webkillerai.core.util.ProgressListener;
import com.webkillerai.core.util.RateLimiter;
import com.webkillerai.core.util.StructuredLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

// ▼ 유지
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.config.FeatureMatrix;
// ▲ 유지

/**
 * 스캔 오케스트레이터:
 *  - crawl → http → scan → 결과 집계
 *  - 기본 구현체(Crawler/HttpAnalyzer/SignatureScanner)
 *  - DI 생성자는 테스트/플러그인 주입용
 *  - 전역 RateLimiter + 고정 스레드풀(동시성=concurrency)로 안전 제어
 *
 * 최적화:
 *  - 액티브(능동) 프로브는 FeatureMatrix 기반으로 전역 스위칭
 *  - 액티브 전용 RPS/게이트/예산 분리
 */
public final class ScanService {

    private static final Logger LOG = LoggerFactory.getLogger(ScanService.class);
    private static final StructuredLog SLOG = StructuredLog.get(ScanService.class);

    private final ScanStats stats = new ScanStats();
    private final ScanConfig config;
    private final RateLimiter rateLimiter;         // 패시브(HTTP 분석)용
    private final ICrawler crawler;
    private final IHttpAnalyzer http;
    private final IScanner scanner;

    // 액티브 프로브 리미터 + 예산
    private final RateLimiter activeLimiter;       // null이면 액티브 비활성
    private final AtomicInteger activeTotal = new AtomicInteger(0);
    private final ConcurrentHashMap<String, AtomicInteger> activePerHost = new ConcurrentHashMap<>();

    // Active runner/engine
    private final ProbeEngine probeEngine;         // 액티브 러너용 엔진
    private final ActiveScanRunner activeRunner;   // 모드/게이트 만족 시 한 줄 실행

    // 게이트(모드/시스템 프로퍼티 해석 결과)
    private final Gate gate;

    private volatile int lastVisitedPages = 0; // 실제 시드(스캔 대상) 개수

    /** 기본 구현(현재 동작 유지) */
    public ScanService(ScanConfig config) {
        this(config, new Crawler(config), new HttpAnalyzer(config), new SignatureScanner());
    }

    /** DI/테스트/플러그인용 */
    public ScanService(ScanConfig config, ICrawler crawler, IHttpAnalyzer http, IScanner scanner) {
        this.config = Objects.requireNonNull(config, "config");
        this.config.validate();
        this.crawler = Objects.requireNonNull(crawler, "crawler");
        this.http = Objects.requireNonNull(http, "http");
        this.scanner = Objects.requireNonNull(scanner, "scanner");

        // 패시브(HTTP) 리미터
        this.rateLimiter = new RateLimiter(config.getRps(), config.getRps());

        // ===== 액티브(능동) 전용 RPS 및 러너 생성 =====
        Mode mode = config.getMode();
        boolean anyActive = FeatureMatrix.isAnyActive(mode);

        // 모드/시스템 프로퍼티 해석(한 번만)
        this.gate = resolveGate(config, mode);

        // 액티브 전용 RPS 리미터
        this.activeLimiter = anyActive
                ? new RateLimiter(Math.max(1, gate.activeRps), Math.max(1, gate.activeRps))
                : null;

        // ActiveScanRunner는 ProbeEngine 필요
        this.probeEngine = anyActive ? new ProbeEngine(config) : null;
        this.activeRunner = anyActive ? new ActiveScanRunner(this.probeEngine) : null;
    }

    /* =========================
       실행 API (오버로드 3종)
       ========================= */

    /** 기존 시그니처 보존 */
    public List<VulnResult> run() {
        return run(ProgressListener.NONE, null);
    }

    /** 진행률 콜백만 받는 오버로드 */
    public List<VulnResult> run(ProgressListener listener) {
        return run(listener, null);
    }

    /** 진행률 + 취소 플래그(옵션) */
    public List<VulnResult> run(ProgressListener listener, AtomicBoolean cancelFlag) {
        final ProgressListener pl = (listener != null) ? listener : ProgressListener.NONE;
        final AtomicBoolean cancel = cancelFlag;

        final int cc = Math.max(1, config.getConcurrency());
        LOG.info("Scan start: target={}, maxDepth={}, rps={}, cc={}",
                config.getTarget(), config.getMaxDepth(), config.getRps(), cc);
        SLOG.info("scan-start",
                "target", String.valueOf(config.getTarget()),
                "maxDepth", config.getMaxDepth(),
                "rps", config.getRps(),
                "cc", cc,
                "mode", String.valueOf(config.getMode()));

        // ---- 0) 크롤 시드 수집 (crawl phase) + 예산 컷 ----
        pl.onProgress(0.0, "crawl", 0, -1);

        final List<URI> seeds = new ArrayList<>();
        final int maxSeeds  = sysInt("wk.crawl.maxSeeds", -1);       // 전체 시드 상한 (기본 꺼짐)
        final int perHost   = sysInt("wk.crawl.maxPerHost", -1);     // 호스트별 시드 상한 (기본 꺼짐)
        final Map<String, Integer> perHostCount = new HashMap<>();

        for (URI u : crawler.crawlSeeds()) {
            checkCancel(cancel);

            if (maxSeeds > 0 && seeds.size() >= maxSeeds) break;

            String host = (u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT));
            if (perHost > 0 && perHostCount.getOrDefault(host, 0) >= perHost) continue;

            if (isStatic(u)) continue; // 정적 리소스는 시드에서 제외

            seeds.add(u);
            perHostCount.merge(host, 1, Integer::sum);
        }
        lastVisitedPages = seeds.size();

        final int total = seeds.size();
        if (total == 0) {
            pl.onProgress(1.0, "export", 0, 0);
            LOG.info("Scan done. totalPages=0, totalIssues=0, maxObservedCC=0");
            SLOG.info("scan-done", "totalPages", 0, "totalIssues", 0, "maxObservedCC", 0);
            return List.of();
        }

        pl.onProgress(0.0, "scan", 0, total);

        // ---- 1) 고정 스레드풀(+역압) 구성 ----
        ExecutorService exec = new ThreadPoolExecutor(
                cc, cc,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(cc * 2),
                new NamedThreadFactory("scan-worker"),
                (r, e) -> {
                    try { e.getQueue().put(r); }
                    catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RejectedExecutionException("Interrupted while enqueueing", ie);
                    }
                }
        );

        final List<Future<List<VulnResult>>> futures = new ArrayList<>(seeds.size());
        final AtomicInteger pageCount   = new AtomicInteger(0);
        final AtomicInteger inFlight    = new AtomicInteger(0);
        final AtomicInteger maxObserved = new AtomicInteger(0);
        final AtomicInteger donePages   = new AtomicInteger(0); // 진행률

        // ---- 2) 작업 제출 ----
        for (URI url : seeds) {
            checkCancel(cancel);
            futures.add(exec.submit(() -> {
                checkCancel(cancel);

                try {
                    rateLimiter.acquire(); // 패시브(HTTP) 리미터 - interruptible
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new CancellationException("Interrupted while rate-limiting");
                }

                int cur = inFlight.incrementAndGet();
                maxObserved.accumulateAndGet(cur, Math::max);
                stats.observeConcurrency(cur);

                long t0 = System.nanoTime();
                int retriesThisCall = 0;

                try {
                    LOG.debug("HTTP analyze: {}", url);

                    checkCancel(cancel);

                    HttpResponseData resp;
                    if (http instanceof HttpAnalyzer ha) {
                        var counting = new CountingRetryPolicy(new DefaultRetryPolicy());
                        resp = ha.analyzeWithRetry(url, counting, new DefaultSleeper());
                        retriesThisCall = counting.getRetryCount();
                    } else {
                        resp = http.analyze(url);
                    }

                    checkCancel(cancel);

                    // 2-1) 시그니처 기반 스캔(기존)
                    List<VulnResult> found = scanner.scan(resp);

                    // 2-2) 액티브 프로브 (게이트 + 예산 + 전용 RPS)
                    if (activeRunner != null && shouldActiveProbe(url, config, pageCount)) {
                        try {
                            if (activeLimiter != null) activeLimiter.acquire(); // 액티브 전용 RPS
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw new CancellationException("Interrupted while active rate-limiting");
                        }
                        List<VulnResult> active = activeRunner.run(config, url);
                        if (!active.isEmpty()) {
                            found.addAll(active);
                            SLOG.info("active-probe",
                                    "url", String.valueOf(url),
                                    "hits", active.size());
                        }
                    }

                    int n = pageCount.incrementAndGet();
                    LOG.info("Scanned {} (page #{}) -> issues={}", url, n, found.size());
                    SLOG.info("page-scanned",
                            "url", String.valueOf(url),
                            "pageNo", n,
                            "issues", found.size());

                    int done = donePages.incrementAndGet();
                    double p = (double) done / (double) total;
                    try {
                        pl.onProgress(Math.max(0.0, Math.min(1.0, p)), "scan", done, total);
                    } catch (Throwable ignore) {}
                    return found;

                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new CancellationException("Interrupted during analyze/scan");

                } finally {
                    long wallMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
                    stats.addAttempts(1L + retriesThisCall);
                    stats.addRetries(retriesThisCall);
                    stats.addWallTimeMs(wallMs);

                    int left = inFlight.decrementAndGet();
                    stats.observeConcurrency(left);
                }
            }));
        }

        // ---- 3) 결과 수집 ----
        List<VulnResult> results = new ArrayList<>();
        try {
            for (Future<List<VulnResult>> f : futures) {
                checkCancel(cancel);
                try {
                    results.addAll(f.get()); // 각 요청은 HttpClient timeout으로 보호됨
                } catch (CancellationException ce) {
                    throw ce;
                } catch (ExecutionException e) {
                    LOG.warn("Scan task failed: {}", e.getCause() != null ? e.getCause().toString() : e.toString());
                    Throwable cause = (e.getCause() != null ? e.getCause() : e);
                    SLOG.error("task-failed", cause, "cause", cause.toString());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new CancellationException("Interrupted while collecting results");
                }
            }
        } finally {
            // ---- 4) 종료 ----
            exec.shutdownNow();
            try {
                exec.awaitTermination(30, TimeUnit.SECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }

        pl.onProgress(1.0, "export", donePages.get(), total);

        LOG.info("Scan done. totalPages={}, totalIssues={}, maxObservedCC={}",
                pageCount.get(), results.size(), maxObserved.get());
        SLOG.info("scan-done",
                "totalPages", pageCount.get(),
                "totalIssues", results.size(),
                "maxObservedCC", maxObserved.get());
        return results;
    }

    /* =========================
       공용 유틸 / 게터
       ========================= */

    private static void checkCancel(AtomicBoolean flag) {
        if (Thread.currentThread().isInterrupted() || (flag != null && flag.get())) {
            throw new CancellationException();
        }
    }

    static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicInteger seq = new AtomicInteger(1);
        NamedThreadFactory(String prefix) { this.prefix = prefix; }
        @Override public Thread newThread(Runnable r) {
            Thread t = new Thread(r, prefix + "-" + seq.getAndIncrement());
            t.setDaemon(true);
            return t;
        }
    }

    public ScanStats.Snapshot getRuntimeSnapshot() {
        return stats.snapshot();
    }

    public int getVisitedPageCount() {
        return lastVisitedPages;
    }

    /* =========================
       최적화 헬퍼들
       ========================= */

    /** 정적 리소스(이미지/폰트/아카이브 등)는 시드/액티브 대상에서 제외 */
    private static boolean isStatic(URI u){
        String p = (u.getPath()==null? "" : u.getPath().toLowerCase(Locale.ROOT));
        int i = p.lastIndexOf('.');
        if (i < 0) return false;
        String ext = p.substring(i+1);
        return Set.of(
                "css","js","png","jpg","jpeg","gif","ico","svg","webp",
                "woff","woff2","ttf","eot","otf","map","pdf","zip","rar","7z",
                "gz","bz2","tar","mp4","mp3","wav","avi","mov","mkv","webm"
        ).contains(ext);
    }

    /** 액티브 프로브 수행 여부 결정 (게이트 + 예산 + 샘플링) */
    private boolean shouldActiveProbe(URI url, ScanConfig cfg, AtomicInteger pageCount){
        // 1) 정적 리소스 컷
        if (isStatic(url)) return false;

        Mode mode = cfg.getMode();

        // 파라미터 필요한 디텍터(XSS/SQLi/SSTI/LFI)
        boolean paramDetectors =
                FeatureMatrix.activeXssReflected(mode) ||
                FeatureMatrix.activeSqli(mode) ||
                FeatureMatrix.activeSsti(mode) ||
                FeatureMatrix.activePathTraversal(mode);

        // 파라미터 불필요(페이지 단위) 디텍터(오픈리다이렉트/CORS/믹스드콘텐츠)
        boolean paramlessDetectors =
                FeatureMatrix.activeOpenRedirect(mode) ||
                FeatureMatrix.activeCors(mode) ||
                FeatureMatrix.activeMixedContent(mode);

        boolean allow = paramlessDetectors;

        // --- 추가: OR만 켜져 있고 redirect-like 파라미터가 없으면 비활성화 ---
        boolean orOnly = FeatureMatrix.activeOpenRedirect(mode)
                && !FeatureMatrix.activeCors(mode)
                && !FeatureMatrix.activeMixedContent(mode)
                && !paramDetectors;

        if (allow && orOnly && !hasRedirectLikeParam(url)) {
            allow = false;
        }
        // --- 여기까지 ---

        // 3) 파라미터 필요한 디텍터는 쿼리/힌트 게이트 적용
        if (paramDetectors && !allow) {
            String q = url.getQuery();
            if (gate.onQueryOnly && (q == null || q.isBlank())) return false;

            if (q != null && !q.isBlank()){
                String lq = q.toLowerCase(java.util.Locale.ROOT);
                boolean hasHint =
                        cfg.getXssParamHints().stream().anyMatch(h -> lq.contains(h.toLowerCase(java.util.Locale.ROOT))) ||
                        cfg.getSqliParamHints().stream().anyMatch(h -> lq.contains(h.toLowerCase(java.util.Locale.ROOT)));
                if (!hasHint) return false;
            }
            allow = true;
        }

        if (!allow) return false;

        // 4) 초반 N 페이지만
        int ordinal = pageCount.get() + 1;
        if (ordinal > gate.firstPages) return false;

        // 5) 샘플링
        if (gate.sample < 1.0 && ThreadLocalRandom.current().nextDouble() > gate.sample) return false;

        // 6) 총/호스트별 예산
        return reserveActiveBudget(url);
    }

    /** 액티브 예산 확보 (총/호스트별 상한) */
    private boolean reserveActiveBudget(URI url){
        int totalMax = gate.maxActive;
        int hostMax  = gate.maxActivePerHost;
        String host = (url.getHost()==null? "" : url.getHost().toLowerCase(java.util.Locale.ROOT));

        if (totalMax > 0 && activeTotal.get() >= totalMax) return false;

        AtomicInteger hostCtr = activePerHost.computeIfAbsent(host, h -> new AtomicInteger(0));
        if (hostMax > 0 && hostCtr.get() >= hostMax) return false;

        activeTotal.incrementAndGet();
        hostCtr.incrementAndGet();
        return true;
    }

    // =========================
    // 게이트 해석/유틸
    // =========================

    private static record Gate(
            int firstPages,
            boolean onQueryOnly,
            double sample,
            int activeRps,
            int maxActive,
            int maxActivePerHost
    ) {}

    private static Gate resolveGate(ScanConfig cfg, Mode mode) {
        final String profile = profileOf(mode);

        // 기본치(FeatureMatrix가 firstPages/onQueryOnly/sample 제공 안 해도 안전하게 동작하도록 로컬 기본 반영)
        final int firstPagesDefault =
                (mode == Mode.AGGRESSIVE) ? 200 : 50;
        final boolean defaultOnQueryOnly =
                (mode == Mode.SAFE_PLUS);
        final double defaultSample =
                (mode == Mode.AGGRESSIVE || mode == Mode.AGGRESSIVE_LITE || mode == Mode.SAFE_PLUS) ? 1.0 : 0.0;

        // per-key: global → per-mode → default
        final int firstPages = sysInt(
                "wk.active.firstPages",
                sysInt("wk." + profile + ".activeFirstPages", firstPagesDefault)
        );

        final boolean onQueryOnly = sysBool(
                "wk.active.onQueryOnly",
                sysBool("wk." + profile + ".activeOnQueryOnly", defaultOnQueryOnly)
        );

        double sample = sysDouble(
                "wk.active.sample",
                sysDouble("wk." + profile + ".sample", defaultSample)
        );
        sample = Math.max(0.0, Math.min(1.0, sample));

        final int rpsDefault = FeatureMatrix.activeDefaultRps(mode, cfg.getRps());
        final int activeRps = sysInt(
                "wk.active.rps",
                sysInt("wk." + profile + ".rps", rpsDefault)
        );

        final int totalMaxDefault = (mode == Mode.AGGRESSIVE) ? 1000 : 400;
        final int hostMaxDefault  = (mode == Mode.AGGRESSIVE) ? 150  : 60;

        final int maxActive = sysInt(
                "wk.active.max",
                sysInt("wk." + profile + ".maxActive", totalMaxDefault)
        );
        final int maxActivePerHost = sysInt(
                "wk.active.maxPerHost",
                sysInt("wk." + profile + ".maxActivePerHost", hostMaxDefault)
        );

        return new Gate(
                Math.max(1, firstPages),
                onQueryOnly,
                sample,
                Math.max(0, activeRps),
                Math.max(0, maxActive),
                Math.max(0, maxActivePerHost)
        );
    }

    private static String profileOf(Mode m) {
        return switch (m) {
            case SAFE -> "safe";
            case SAFE_PLUS -> "safeplus";
            case AGGRESSIVE_LITE -> "agglite";
            case AGGRESSIVE -> "aggressive";
        };
    }

    /** 시스템 정수 프로퍼티 파싱 유틸 */
    private static int sysInt(String key, int def){
        try { return Integer.parseInt(System.getProperty(key, String.valueOf(def)).trim()); }
        catch (Exception e){ return def; }
    }

    /** 시스템 불리언 프로퍼티 파싱 유틸 */
    private static boolean sysBool(String key, boolean def){
        String v = System.getProperty(key);
        if (v == null) return def;
        v = v.trim().toLowerCase(Locale.ROOT);
        return switch (v) {
            case "1","true","on","yes","y" -> true;
            case "0","false","off","no","n" -> false;
            default -> def;
        };
    }

    /** 시스템 더블 프로퍼티 파싱 유틸 */
    private static double sysDouble(String key, double def){
        try { return Double.parseDouble(System.getProperty(key, String.valueOf(def)).trim()); }
        catch (Exception e){ return def; }
    }

    private static double clamp01(double v){ return Math.max(0.0, Math.min(1.0, v)); }

    /** redirect/returnUrl/url/next 같은 힌트 파라미터가 있는지 간단 체크 */
    private static boolean hasRedirectLikeParam(URI url){
        String q = url.getQuery();
        if (q == null || q.isBlank()) return false;
        for (String pair : q.split("&")){
            if (pair.isEmpty()) continue;
            String key = pair.split("=", 2)[0].toLowerCase(Locale.ROOT);
            if (key.contains("redirect") || key.contains("returnurl") || key.equals("url") || key.equals("next")) {
                return true;
            }
        }
        return false;
    }
}
