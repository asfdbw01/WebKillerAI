package com.webkillerai.core.service.export;

import static com.webkillerai.core.service.export.ReportNaming.*;

import com.webkillerai.core.config.FeatureMatrix;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

// ▼ 모드 표기를 위해
import com.webkillerai.core.model.Mode;

/**
 * 보고서형 JSON(v1.3) Exporter.
 * - 사람/AI가 바로 렌더 가능한 구조(meta/summary/issues/rootCause/sections/limitations/appendix).
 * - Evidence 세부 노출은 시스템 프로퍼티(-Dwk.json.showEvidenceDetails) 우선,
 *   없으면 FeatureMatrix.isAnyActive(mode) 기반으로 ON/OFF.
 */
public class JsonReportExporter implements ReportExporter {

    // 런타임 텔레메트리/페이지 수를 가져오기 위한 선택적 소스
    private com.webkillerai.core.service.ScanService runtimeSource;

    /** 체이닝용: Exporter 생성 후 .withRuntime(scanService)로 런타임 값을 주입 */
    public JsonReportExporter withRuntime(com.webkillerai.core.service.ScanService svc) {
        this.runtimeSource = svc;
        return this;
    }

    @Override
    public Path export(Path baseDir, ScanConfig cfg, List<VulnResult> results, String startedIso) throws Exception {
        var ctx = context(baseDir, cfg.getTarget(), startedIso);
        Files.createDirectories(reportsDir(ctx));
        Path outFile = jsonPath(ctx);

        String json = buildJsonV13(cfg, results, startedIso);
        Files.writeString(outFile, json, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        return outFile;
    }

    // ================= JSON v1.3 빌더 =================
    private String buildJsonV13(ScanConfig cfg, List<VulnResult> results, String startedIso) {
        int high=0, med=0, low=0;
        for (var v : results) {
            Severity s = v.getSeverity();
            if (s == Severity.HIGH || s == Severity.CRITICAL) high++;
            else if (s == Severity.MEDIUM) med++;
            else if (s == Severity.LOW || s == Severity.INFO) low++; // INFO도 LOW로 합산
        }
        int total = results.size();
        int riskScore = calcRiskScore(high, med, low, total);

        List<String> highlights = results.stream()
                .sorted(Comparator.comparing(VulnResult::getSeverity).reversed())
                .limit(3)
                .map(v -> safeOr(v.getDescription(), v.getIssueType().name()))
                .collect(Collectors.toList());

        String execSummary = String.format(
                "대상 %s 를 %s 모드로 %d RPS로 점검했습니다. 총 %d건의 이슈가 확인되었고 최상위 심각도는 %s입니다.",
                cfg.getTarget(), cfg.getMode().name(), cfg.getRps(), total, topSeverity(high, med, low)
        );

        // 방문 페이지 수(크롤러 실제 결과)와 런타임 텔레메트리 구성
        int visitedPages = (runtimeSource != null) ? runtimeSource.getVisitedPageCount() : Math.max(1, total);
        StringBuilder runtimeJson = new StringBuilder()
            .append("{ \"rps\": ").append(cfg.getRps())
            .append(", \"concurrency\": ").append(cfg.getConcurrency())
            .append(", \"timeoutMs\": ").append(cfg.getTimeoutMs());
        if (runtimeSource != null) {
            var rt = runtimeSource.getRuntimeSnapshot();
            runtimeJson.append(", \"requestsTotal\": ").append(rt.requestsTotal)
                       .append(", \"retriesTotal\": ").append(rt.retriesTotal)
                       .append(", \"maxObservedConcurrency\": ").append(rt.maxObservedConcurrency)
                       .append(", \"avgLatencyMs\": ").append(rt.avgLatencyMs);
        }
        runtimeJson.append(" }");

        boolean showEviDetails = showEvidenceDetails(cfg); // FeatureMatrix + 시스템 프로퍼티 기반

        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\n");

        // meta
        sb.append("  \"meta\": {\n")
          .append("    \"reportVersion\": \"1.3\",\n")
          .append("    \"generatedAt\": ").append(q(Instant.now().toString())).append(",\n")
          .append("    \"startedAt\": ").append(q(startedIso)).append(",\n")
          .append("    \"mode\": ").append(q(cfg.getMode().name())).append(",\n")
          .append("    \"target\": ").append(q(cfg.getTarget())).append(",\n")
          .append("    \"scope\": { ")
            .append("\"sameDomainOnly\": ").append(cfg.isSameDomainOnly()).append(", ")
            .append("\"maxDepth\": ").append(cfg.getMaxDepth()).append(", ")
            .append("\"maxPages\": ").append(visitedPages).append(", ")
            .append("\"excludes\": ").append(toArray(nullSafe(getExcludePathsSafe(cfg))))
          .append(" },\n")
          .append("    \"runtime\": ").append(runtimeJson).append(",\n")
          .append("    \"engine\": { ")
            .append("\"scanners\": [\"SignatureScanner@0.1.0\"")
              .append(cfg.getMode()==Mode.SAFE_PLUS? ",\"ActiveProbes@0.4\"":"")
            .append("], ")
            .append("\"rulesetVersion\": ").append(q("sig-" + LocalDate.now()))
          .append(" },\n")
          .append("    \"counts\": { \"pages\": ").append(visitedPages).append(", \"issues\": ").append(total).append(" }\n")
          .append("  },\n");

        // summary
        sb.append("  \"summary\": {\n")
          .append("    \"riskScore\": ").append(riskScore).append(",\n")
          .append("    \"severityTop\": ").append(q(topSeverity(high, med, low))).append(",\n")
          .append("    \"distribution\": { \"HIGH\": ").append(high).append(", \"MEDIUM\": ").append(med).append(", \"LOW\": ").append(low).append(" },\n")
          .append("    \"keyFindings\": ").append(toArray(highlights)).append("\n")
          .append("  },\n");

        // findingsOverview
        sb.append("  \"findingsOverview\": ").append(groupByType(results)).append(",\n");

        // issues
        sb.append("  \"issues\": [\n");
        for (int i = 0; i < results.size(); i++) {
            sb.append(buildIssue(cfg, results.get(i), showEviDetails));
            if (i < results.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        // sections
        sb.append("  \"sections\": {\n")
          .append("    \"executiveSummary\": ").append(q(execSummary)).append(",\n")
          .append("    \"technicalNotes\": ").append(q("헤더/콘텐츠 기반 시그니처 매칭 + (모드에 따라) 경량 액티브 프로브.")).append(",\n")
          .append("    \"nextSteps\": [")
          .append(q("보안 헤더(CSP/XCTO/XFO/Referrer-Policy) 검토 및 적용")).append(", ")
          .append(q("템플릿 위험 API(document.write/innerHTML 등) 제거"))
          .append("]\n")
          .append("  },\n");

        // limitations
        sb.append("  \"limitations\": {\n")
          .append("    \"assessedGaps\": ").append(toArray(List.of(
              "GET/HEAD 중심(POST·상태변경 기반 취약점 미탐 가능)",
              "CSR/로그인 이후 렌더 콘텐츠 일부 누락 가능",
              "정규식 기반 문맥 추정 한계"
          ))).append(",\n")
          .append("    \"blindSpots\": ").append(toArray(List.of(
              "권한 레벨별 차등 응답(관리자/내부망)",
              "서드파티 스크립트 런타임 행위",
              "A/B·Feature Flag에 의한 응답 분기"
          ))).append("\n")
          .append("  },\n");

        // appendix
        sb.append("  \"appendix\": {\n")
          .append("    \"signaturesUsed\": ").append(toArray(List.of(
              "CSP_MISSING","XCTO_MISSING","XFO_MISSING","XSS_SINK_REGEX","SQL_ERROR_REGEX"
          ))).append(",\n")
          .append("    \"scoring\": { ")
            .append("\"weights\": { \"sev\": 0.55, \"count\": 0.15, \"ml\": 0.00, \"policy\": 0.30 }, ")
            .append("\"severityMap\": { \"HIGH\": 90, \"MEDIUM\": 60, \"LOW\": 30 }")
          .append(" }\n")
          .append("  }\n");

        sb.append("}\n");
        return sb.toString();
    }

    private String buildIssue(ScanConfig cfg, VulnResult v, boolean showEviDetails) {
        var root = inferRootCause(v); // 경량 원인 규칙(내장)

        // evidence 필드 구성
        String reqLine = showEviDetails ? safeOr(v.getRequestLine(), null) : null;
        String snippet = showEviDetails ? safeOr(firstNonBlank(v.getEvidenceSnippet(), v.getEvidence()), null) : null;
        String summary = safeTrim(v.getEvidence(), 140); // 하위호환(간단 요약)

        StringBuilder sb = new StringBuilder(512);
        sb.append("    {")
          .append("\"id\": ").append(q(makeId(v))).append(", ")
          .append("\"url\": ").append(q(v.getUrl() != null ? v.getUrl().toString() : "")).append(", ")
          .append("\"issueType\": ").append(q(v.getIssueType().name())).append(", ")
          .append("\"severity\": ").append(q(v.getSeverity().name())).append(", ")
          .append("\"riskScore\": ").append(v.getRiskScore() == null ? "null" : String.valueOf(v.getRiskScore())).append(", ")

          .append("\"detection\": {")
            .append("\"method\": [\"passive\"").append(showEviDetails ? ",\"evidence-details\"" : "").append("], ")
            .append("\"signals\": {")
              .append("\"regexHit\": ").append(toArray(guessRegexHits(v))).append(", ")
              .append("\"mlProba\": {\"XSS\": 0.00, \"SQLI\": 0.00}")
            .append("}, ")
            .append("\"confidence\": ").append(fmt(v.getConfidence()))
          .append("}, ")

          .append("\"rootCause\": {")
            .append("\"text\": ").append(q(root.text())).append(", ")
            .append("\"confidence\": ").append(fmt(root.confidence())).append(", ")
            .append("\"vector\": ").append(toObject(root.vector())).append(", ")
            .append("\"missingControls\": ").append(toArray(root.missingControls())).append(", ")
            .append("\"factors\": ").append(toArray(root.factors()))
          .append("}, ")

          .append("\"description\": ").append(q(safeOr(v.getDescription(), v.getIssueType().name()))).append(", ")

          .append("\"evidence\": {")
            .append("\"summary\": ").append(q(summary)).append(", ")
            .append("\"requestLine\": ").append(q(reqLine)).append(", ")
            .append("\"snippet\": ").append(q(snippet)).append(", ")
            // 하위호환 필드(예전 파서가 쓰는 배열)
            .append("\"snippets\": ").append(toArray(summary.isEmpty() ? List.of() : List.of(summary))).append(", ")
            .append("\"contentType\": ").append(q(null)).append(", ")
            .append("\"responseHash\": ").append(q(null)).append(", ")
            .append("\"length\": ").append(0)
          .append("}, ")

          .append("\"remediation\": ").append(toArray(defaultRemediation(v))).append(", ")
          .append("\"detectedAt\": ").append(q(v.getDetectedAt().toString())).append(", ")
          .append("\"tags\": ").append(toArray(List.of(
                (cfg.getMode() == Mode.SAFE_PLUS ? "SAFE_PLUS" : "SAFE"),
                "passive"))).append("}");

        return sb.toString();
    }

    // ================= 경량 RootCause 규칙 =================
    private record RootCause(String text, double confidence, Map<String,String> vector,
                             List<String> missingControls, List<String> factors) {}

    private RootCause inferRootCause(VulnResult v) {
        String ev = safeOr(v.getEvidence(), "");
        String desc = safeOr(v.getDescription(), "");
        String all = (ev + " " + desc).toLowerCase(Locale.ROOT);
        String type = v.getIssueType().name();

        String param = firstParam(v.getUrl());
        if (type.contains("XSS")) {
            String ctx = guessContext(all);
            boolean sink = all.matches(".*(<script|on\\w+=|javascript:|document\\.write|innerhtml\\s*=|eval\\s*\\().*");
            String text = sink
                ? "사용자 입력(" + param + ")이 " + prettyContext(ctx) + "에 반사되었으나 출력 인코딩이 적용되지 않음"
                : "사용자 입력(" + param + ")이 페이지에 반사될 가능성이 있으며 출력 인코딩/검증이 불충분할 수 있음";
            double conf = sink ? 0.78 : 0.62;
            return new RootCause(text, conf,
                    Map.of("kind","reflected","context",ctx,"param",param,"sink", sink? "present":"unknown"),
                    List.of(), factors(v.getUrl(), sink));
        }
        if (type.contains("SQL")) {
            boolean sqlErr = all.matches(".*(sqlstate|you have an error in your sql syntax|ora-\\d{5}|odbc driver|statementinvalid).*");
            String text = sqlErr
                ? "입력값(" + param + ")이 쿼리에 직접 연결되어 DB 오류가 노출됨(파라미터 바인딩/검증 미흡)"
                : "입력 검증/파라미터 바인딩이 불충분할 가능성이 있으며 오류 처리 미흡으로 정보 노출 가능";
            double conf = sqlErr ? 0.75 : 0.55;
            return new RootCause(text, conf, Map.of("kind","error-leak","param",param), List.of(), factors(v.getUrl(), sqlErr));
        }
        if (type.contains("HEADER")) {
            String text = "보안 헤더 정책이 미설정/미흡하여 콘텐츠·프레이밍·MIME 강제 등 방어가 부재";
            return new RootCause(text, 0.70, Map.of("kind","policy"), List.of(), factors(v.getUrl(), true));
        }
        return new RootCause("구성/정책 미흡으로 위험이 노출될 수 있음", 0.50, Map.of("kind","generic"), List.of(), factors(v.getUrl(), false));
    }

    // ================= 헬퍼 =================
    private static String makeId(VulnResult v){
        return (v.getIssueType().name().substring(0, Math.min(3, v.getIssueType().name().length())) + "-" + Math.abs(v.hashCode()));
    }
    private static List<String> guessRegexHits(VulnResult v){
        String e = safeOr(v.getEvidence(), "").toLowerCase(Locale.ROOT);
        List<String> hits = new ArrayList<>();
        if (e.contains("<script") || e.contains("innerhtml")) hits.add("<script|innerHTML=");
        if (e.contains("sqlstate") || e.contains("you have an error in your sql syntax")) hits.add("SQL_ERROR_REGEX");
        return hits;
    }
    private static List<String> defaultRemediation(VulnResult v){
        String t = v.getIssueType().name();
        if (t.contains("XSS")) return List.of("출력 인코딩 적용", "CSP 적용", "DOM 위험 API 제거");
        if (t.contains("SQL")) return List.of("파라미터 바인딩 사용", "오류 메시지 마스킹");
        if (t.contains("HEADER")) return List.of("CSP/XCTO/XFO/Referrer-Policy 구성");
        return List.of("보안 구성 점검");
    }
    private static String groupByType(List<VulnResult> results){
        Map<String, Long> g = results.stream()
                .collect(Collectors.groupingBy(v -> v.getIssueType().name(), Collectors.counting()));
        String items = g.entrySet().stream()
                .map(e -> String.format("{\"issueType\":%s,\"count\":%d}", q(e.getKey()), e.getValue()))
                .collect(Collectors.joining(","));
        return "[" + items + "]";
    }

    private static int calcRiskScore(int h,int m,int l,int total){
        int sev = h*90 + m*60 + l*30;
        int policy = (h+m)>0 ? 20 : 0;
        int count = Math.min(10, total*2);
        int score = (int)Math.round(0.55*(sev/Math.max(1.0,total)) + 0.15*count + 0.30*policy);
        return Math.max(0, Math.min(100, score));
    }

    private static String topSeverity(int h, int m, int l){
        if (h>0) return "HIGH"; if (m>0) return "MEDIUM"; if (l>0) return "LOW"; return "NONE";
    }

    private static String q(String s){ return s == null ? "null" : "\"" + s.replace("\\","\\\\").replace("\"","\\\"") + "\""; }
    private static String toArray(List<String> list){ return "[" + list.stream().map(JsonReportExporter::q).collect(Collectors.joining(",")) + "]"; }
    private static String toObject(Map<String,String> m){ return "{" + m.entrySet().stream().map(e -> q(e.getKey())+":"+q(e.getValue())).collect(Collectors.joining(",")) + "}"; }
    private static String safeOr(String s, String alt){ return (s == null || s.isBlank()) ? alt : s; }
    private static String safeTrim(String s, int max){ if (s == null) return ""; return s.length()<=max? s : s.substring(0, max)+"..."; }
    private static String firstNonBlank(String a, String b){ return (a!=null && !a.isBlank()) ? a : (b==null? "" : b); }

    private static String firstParam(URI url){
        if (url == null || url.getQuery() == null) return "?";
        String q = url.getQuery();
        int i = q.indexOf('=');
        if (i > 0) return q.substring(0, i);
        int a = q.indexOf('&');
        return a > 0 ? q.substring(0, a) : q;
    }
    private static List<String> factors(URI url, boolean primary){
        List<String> f = new ArrayList<>();
        if (url != null) f.add("url:"+url);
        if (primary) f.add("pattern:hit");
        return f;
    }
    private static String guessContext(String s){
        if (s.contains("innerhtml") || s.contains("onclick")) return "html_attr";
        if (s.contains("document.write") || s.contains("eval(")) return "js_string";
        if (s.contains("href=") || s.contains("src=") || s.contains("javascript:")) return "url";
        return "html_text";
    }
    private static String fmt(double d) {
        return String.format(java.util.Locale.ROOT, "%.2f", d);
    }
    private static String prettyContext(String c) {
        return switch (c) {
            case "html_attr" -> "HTML 속성 컨텍스트";
            case "js_string" -> "JavaScript 문자열";
            case "url"       -> "URL 컨텍스트";
            default          -> "HTML 문맥";
        };
    }

    // ---------- evidence 표시 토글 ----------
    private static boolean showEvidenceDetails(ScanConfig cfg) {
        String p = System.getProperty("wk.json.showEvidenceDetails", "")
                         .trim().toLowerCase(java.util.Locale.ROOT);
        if (p.equals("on") || p.equals("true") || p.equals("1"))  return true;
        if (p.equals("off")|| p.equals("false")|| p.equals("0"))  return false;
        // 기본: 모드에서 액티브가 하나라도 켜져 있으면 상세 evidence 포함
        return FeatureMatrix.isAnyActive(cfg.getMode());
    }

    // ---------- excludePaths 안전 접근자 ----------
    @SuppressWarnings("unchecked")
    private static List<String> getExcludePathsSafe(ScanConfig cfg){
        try {
            var m = cfg.getClass().getMethod("getExcludePaths");
            Object v = m.invoke(cfg);
            if (v instanceof List) return (List<String>) v;
        } catch (Exception ignore) { }
        try {
            var m = cfg.getClass().getMethod("getCrawler");
            Object cr = m.invoke(cfg);
            if (cr != null) {
                try {
                    var m2 = cr.getClass().getMethod("getExcludePaths");
                    Object v2 = m2.invoke(cr);
                    if (v2 instanceof List) return (List<String>) v2;
                } catch (Exception ignore) {}
            }
        } catch (Exception ignore) { }
        return List.of();
    }
    private static List<String> nullSafe(List<String> l){ return (l==null) ? List.of() : l; }
}
