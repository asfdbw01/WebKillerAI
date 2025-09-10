package com.webkillerai.core.model;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * 스캔 설정 (scan.yml 매핑 대상) — 순수 설정 보관용.
 * 모드 선택(CLI/ENV/시스템 프로퍼티)은 외부 ModeResolver 사용 권장.
 *
 * 중요: Mode 는 외부 enum(com.webkillerai.core.model.Mode)을 사용한다.
 */
public final class ScanConfig {

    /** (과거 호환용) 단일 출력 형식 enum — 실제 출력은 Exporter 쪽에서 제어 */
    public enum OutputFormat { JSON }

    /** 크롤러 관련 하위 설정: YAML의 `crawler:` 섹션과 매핑 */
    public static final class CrawlerCfg {
        /** robots.txt 존중 여부 (기본 true) */
        private boolean respectRobots = true;
        /** robots.txt 캐시 TTL(분). 기본 30. 0이면 캐시 미사용 의미로 해석 가능 */
        private int cacheTtlMinutes = 30;

        public boolean isRespectRobots() { return respectRobots; }
        public void setRespectRobots(boolean respectRobots) { this.respectRobots = respectRobots; }

        public int getCacheTtlMinutes() { return cacheTtlMinutes; }
        public void setCacheTtlMinutes(int cacheTtlMinutes) { this.cacheTtlMinutes = cacheTtlMinutes; }
    }

    // ---------- 기본 필드 ----------
    private String target;               // 시작 URL (필수)
    private int maxDepth = 2;            // 크롤링 최대 깊이
    private boolean sameDomainOnly = true;

    /** 모드: 외부 enum 사용. 기본값은 SAFE */
    private Mode mode = Mode.SAFE;

    private Duration timeout = Duration.ofSeconds(10); // 요청 타임아웃
    private int concurrency = 4;         // 동시 요청 상한
    private boolean followRedirects = true;
    private Path outputDir = Path.of("out");
    private OutputFormat outputFormat = OutputFormat.JSON;
    private int rps = 10;

    /** YAML `crawler:` 섹션 매핑 */
    private CrawlerCfg crawler = new CrawlerCfg();

    // ---------- v0.4 SAFE_PLUS 최소 추가 ----------
    /** URL당 주입 파라미터 최대 개수 (가드레일: SAFE_PLUS용 기본) */
    private int maxParamsPerUrl = 3;

    /** XSS 파라미터 힌트(없으면 기본 리스트 사용) */
    private List<String> xssParamHints = List.of("q","search","s","query","keyword");

    /** SQLi 파라미터 힌트(없으면 기본 리스트 사용) */
    private List<String> sqliParamHints = List.of("id","uid","user","no","prod","cat","page");

    // ---------- AGGRESSIVE_LITE(이번 라운드 구현용) ----------
    /** AGGRESSIVE_LITE 전용 하위 설정 */
    public static final class Aggressive {
        private int maxParamsPerUrl = 3;      // URL당 변조 파라미터 상한
        private int runTimeBudgetMs = 60_000; // 전체 실행 예산(밀리초)
        private boolean enableOpenRedirect = true;
        private boolean enablePathTraversal = true;
        private boolean enableSSTI = true;
        private boolean enableMixedContent = true;

        public int getMaxParamsPerUrl() { return maxParamsPerUrl; }
        public Aggressive setMaxParamsPerUrl(int v){ this.maxParamsPerUrl = Math.max(1, v); return this; }

        public int getRunTimeBudgetMs(){ return runTimeBudgetMs; }
        public Aggressive setRunTimeBudgetMs(int v){ this.runTimeBudgetMs = Math.max(1000, v); return this; }

        public boolean isEnableOpenRedirect(){ return enableOpenRedirect; }
        public Aggressive setEnableOpenRedirect(boolean v){ this.enableOpenRedirect = v; return this; }

        public boolean isEnablePathTraversal(){ return enablePathTraversal; }
        public Aggressive setEnablePathTraversal(boolean v){ this.enablePathTraversal = v; return this; }

        public boolean isEnableSSTI(){ return enableSSTI; }
        public Aggressive setEnableSSTI(boolean v){ this.enableSSTI = v; return this; }

        public boolean isEnableMixedContent(){ return enableMixedContent; }
        public Aggressive setEnableMixedContent(boolean v){ this.enableMixedContent = v; return this; }
    }
    private final Aggressive aggressive = new Aggressive();

    // ---------- getters ----------
    public String getTarget() { return target; }
    public int getMaxDepth() { return maxDepth; }
    public boolean isSameDomainOnly() { return sameDomainOnly; }

    /** 모드: 순수 설정값 반환(널가드 포함). 외부 오버라이드는 ModeResolver 권장 */
    public Mode getMode() { return mode == null ? Mode.SAFE : mode; }

    public Duration getTimeout() { return timeout; }
    public int getConcurrency() { return concurrency; }
    public boolean isFollowRedirects() { return followRedirects; }
    public Path getOutputDir() { return outputDir; }
    public OutputFormat getOutputFormat() { return outputFormat; }
    public int getRps() { return rps; }
    public CrawlerCfg getCrawler() { return crawler; }

    /** v0.4 SAFE_PLUS 게터 */
    public int getMaxParamsPerUrl() { return maxParamsPerUrl; }
    public List<String> getXssParamHints() { return xssParamHints; }
    public List<String> getSqliParamHints() { return sqliParamHints; }

    /** AGGRESSIVE_LITE 설정 접근자 */
    public Aggressive aggressive(){ return aggressive; }

    // ---------- fluent setters ----------
    public void setRps(int rps) { this.rps = rps; } // 기존 스타일 유지
    public ScanConfig setTarget(String target) { this.target = target; return this; }
    public ScanConfig setMaxDepth(int maxDepth) { this.maxDepth = maxDepth; return this; }
    public ScanConfig setSameDomainOnly(boolean v) { this.sameDomainOnly = v; return this; }

    /** 외부 enum Mode 사용 (AGGRESSIVE_LITE 포함) */
    public ScanConfig setMode(Mode mode) {
        this.mode = (mode != null ? mode : Mode.SAFE);
        return this;
    }

    public ScanConfig setTimeout(Duration timeout) { this.timeout = timeout; return this; }
    public ScanConfig setConcurrency(int concurrency) { this.concurrency = Math.max(1, concurrency); return this; }
    public ScanConfig setFollowRedirects(boolean v) { this.followRedirects = v; return this; }
    public ScanConfig setOutputDir(Path outputDir) { this.outputDir = outputDir; return this; }
    public ScanConfig setOutputFormat(OutputFormat outputFormat) { this.outputFormat = outputFormat; return this; }
    public ScanConfig setCrawler(CrawlerCfg crawler) { this.crawler = (crawler != null ? crawler : new CrawlerCfg()); return this; }

    /** v0.4 SAFE_PLUS 세터 */
    public ScanConfig setMaxParamsPerUrl(int maxParamsPerUrl) {
        this.maxParamsPerUrl = Math.max(1, maxParamsPerUrl);
        return this;
    }
    public ScanConfig setXssParamHints(List<String> hints) {
        if (hints != null && !hints.isEmpty()) this.xssParamHints = List.copyOf(hints);
        return this;
    }
    public ScanConfig setSqliParamHints(List<String> hints) {
        if (hints != null && !hints.isEmpty()) this.sqliParamHints = List.copyOf(hints);
        return this;
    }

    // ---------- validate ----------
    public void validate() {
        Objects.requireNonNull(target, "target");
        if (maxDepth < 0) throw new IllegalArgumentException("maxDepth must be >= 0");
        if (concurrency < 1) throw new IllegalArgumentException("concurrency must be >= 1");
        if (timeout == null || timeout.isNegative() || timeout.isZero())
            throw new IllegalArgumentException("timeout must be > 0");
        if (rps <= 0) throw new IllegalArgumentException("rps must be > 0");
        Objects.requireNonNull(outputDir, "outputDir");
        Objects.requireNonNull(outputFormat, "outputFormat");

        Objects.requireNonNull(crawler, "crawler");
        if (crawler.getCacheTtlMinutes() < 0)
            throw new IllegalArgumentException("crawler.cacheTtlMinutes must be >= 0");

        // SAFE_PLUS 필드
        if (maxParamsPerUrl < 1) throw new IllegalArgumentException("maxParamsPerUrl must be >= 1");
        Objects.requireNonNull(xssParamHints, "xssParamHints");
        Objects.requireNonNull(sqliParamHints, "sqliParamHints");

        // 모드 널가드
        if (mode == null) mode = Mode.SAFE;

        // AGGRESSIVE_LITE 검증
        if (aggressive.getMaxParamsPerUrl() < 1) {
            throw new IllegalArgumentException("aggressive.maxParamsPerUrl must be >= 1");
        }
        if (aggressive.getRunTimeBudgetMs() < 1000) {
            throw new IllegalArgumentException("aggressive.runTimeBudgetMs must be >= 1000");
        }
    }

    // ---------- helpers ----------
    public static ScanConfig defaults() { return new ScanConfig(); }

    /** 기존 코드 호환용: 밀리초(long) 반환 */
    public long getTimeoutMs() { return timeout.toMillis(); }

    /** HttpClient 등 int ms 필요 시 편의 메서드 */
    public int getTimeoutMsInt() {
        long ms = getTimeoutMs();
        return (ms > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int) ms;
    }

    public ScanConfig setTimeoutMs(long ms) {
        this.timeout = Duration.ofMillis(Math.max(1, ms));
        return this;
    }
}
