package com.webkillerai.core.service.export;

import com.webkillerai.core.config.FeatureMatrix;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.ScanStats;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.util.RiskUtil;
import com.webkillerai.core.util.RiskUtil.RiskSummary;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Year;
import java.util.*;

public class HtmlReportExporter implements ReportExporter {

    private ScanStats stats; // 선택 주입

    /** 선택: 런타임 통계 주입 */
    public HtmlReportExporter withStats(ScanStats stats) {
        this.stats = stats;
        return this;
    }

    @Override
    public Path export(Path baseDir, ScanConfig cfg, List<VulnResult> results, String startedIso) {
        Objects.requireNonNull(cfg, "cfg");
        final Path outRoot = (baseDir != null) ? baseDir : Paths.get("out");

        final String host = extractHost(cfg.getTarget());
        final String slug = makeSlug(cfg.getTarget());
        final String ts   = formatTs(startedIso);

        final Path dir = outRoot.resolve("reports").resolve(host);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final Path html = dir.resolve("scan-" + slug + "-" + ts + ".html");
        final String content = buildHtml(cfg, results, startedIso);
        try {
            Files.writeString(html, content, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return html;
    }

    private static String formatTs(String startedIso) {
        try {
            var ins = java.time.Instant.parse(startedIso);
            var ldt = java.time.LocalDateTime.ofInstant(ins, java.time.ZoneId.systemDefault());
            return java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmm").format(ldt);
        } catch (Exception e) {
            return java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmm")
                    .format(java.time.LocalDateTime.now());
        }
    }

    // ---------------- render ----------------

    private String buildHtml(ScanConfig cfg, List<VulnResult> issuesIn, String startedIso) {
        // Evidence 표시 길이/줄수는 시스템 프로퍼티로 조절 가능
        int evMaxChars   = sysInt("wk.html.evi.maxChars", 512); // 기본 512
        int evClampLines = sysInt("wk.html.evi.clampLines", 2); // 기본 2
        boolean showFullEvidence = showEvidenceDetails(cfg);    // ← 토글

        List<VulnResult> issues = (issuesIn == null) ? List.of() : issuesIn;

        // severity 분포(모든 레벨 포함)
        Map<Severity, Long> dist = new LinkedHashMap<>();
        for (Severity s : Severity.values()) dist.put(s, 0L);
        for (VulnResult v : issues) dist.computeIfPresent(v.getSeverity(), (k, old) -> old + 1);

        long totalIssues = issues.size();
        String topSeverity = dist.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .map(e -> e.getKey().name() + "(" + e.getValue() + ")")
                .findFirst().orElse("NONE");

        // H/M/L (CRITICAL→HIGH, INFO→LOW로 합산)
        long cHigh = dist.getOrDefault(Severity.HIGH, 0L);
        long cCritical = dist.getOrDefault(Severity.CRITICAL, 0L);
        long cMed  = dist.getOrDefault(Severity.MEDIUM, 0L);
        long cLow  = dist.getOrDefault(Severity.LOW, 0L);
        long cInfo = dist.getOrDefault(Severity.INFO, 0L);

        int high = Math.toIntExact(cHigh + cCritical);
        int med  = Math.toIntExact(cMed);
        int low  = Math.toIntExact(cLow + cInfo);

        // Overall Risk (정책 스코어)
        int overallRisk = calcRiskScore(high, med, low, (int) totalIssues);
        String overCls = riskClass(overallRisk);

        // ★ Risk 요약 (Avg / 95p / Max) — null riskScore는 severity→risk 맵으로 대체
        RiskSummary rs = RiskUtil.summarize(issues);

        // Excludes count (config 버전별 대응: 리플렉션)
        int excludesCount = excludeCountFromConfig(cfg);

        // 추가 스타일
        String extraStyle =
                "<style>\n" +
                "  :root{ --ev-lines: " + evClampLines + "; }\n" +
                "  body{margin:24px}\n" +
                "  h1{font-size:22px;margin:0 0 6px}\n" +
                "  h2{font-size:18px;margin:16px 0 8px}\n" +
                "  .sub{opacity:.8}\n" +
                "  .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}\n" +
                "  @media (max-width:960px){.grid{grid-template-columns:1fr}}\n" +
                "  thead tr.filters input[type=\"search\"]{ width:100%; box-sizing:border-box; padding:6px 8px; }\n" +
                "  .ev{ display:-webkit-box; -webkit-box-orient:vertical; overflow:hidden; -webkit-line-clamp: var(--ev-lines); white-space:pre-wrap; }\n" +
                "  .summary-badges{display:flex;gap:8px;align-items:center;margin-top:6px}\n" +
                "  .chip{padding:2px 8px;border-radius:10px;border:1px solid rgba(0,0,0,.1)}\n" +
                "  .chip-excludes{opacity:.9}\n" +
                "</style>";

        StringBuilder sb = new StringBuilder(16_384);
        sb.append("<!doctype html><html><head><meta charset='utf-8'>")
          .append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
          .append("<title>WebKillerAI Report - ").append(esc(cfg.getTarget())).append("</title>")
          .append(HtmlReportTemplates.css())
          .append(extraStyle)
          .append("</head><body>");

        // Header
        String title = "WebKillerAI — Risk Report";
        String subtitle = "Target: " + esc(cfg.getTarget())
                + " · Mode: " + esc(cfg.getMode() == null ? "UNKNOWN" : String.valueOf(cfg.getMode()))
                + " · Started: " + esc(startedIso != null ? startedIso : "n/a")
                + " · Generated: " + esc(java.time.ZonedDateTime.now().toString());
        sb.append(HtmlReportTemplates.header(title, subtitle));

        // Summary (stats가 있으면 스냅샷으로 표시)
        sb.append("<div class='card'><h2>Executive Summary</h2><div class='grid'>");
        kv(sb, "Total Issues", String.valueOf(totalIssues));
        kv(sb, "Top Severity", topSeverity);
        kv(sb, "Scope", (cfg.isSameDomainOnly() ? "Same-domain" : "Cross-domain") + ", depth ≤ " + cfg.getMaxDepth());
        // Overall Risk 배지
        kvHtml(sb, "Overall Risk", riskBadge(overallRisk, overCls));

        if (stats != null) {
            var snap = stats.snapshot();
            kv(sb, "Requests (total)", String.valueOf(snap.requestsTotal));
            kv(sb, "Retries", String.valueOf(snap.retriesTotal));
            kv(sb, "Concurrency (max)", String.valueOf(snap.maxObservedConcurrency));
            kv(sb, "Avg Latency (ms)", String.valueOf(snap.avgLatencyMs));
        }
        sb.append("</div>"); // grid

        // Exec Summary 배지(Avg/95p) + Excludes 칩 (Max는 title로)
        sb.append(summaryHeaderAvgP95(rs.avg(), rs.p95(), rs.max(), excludesCount));

        // Summary Bar
        sb.append(HtmlReportTemplates.summaryBar(high, med, low));
        sb.append("</div>"); // card

        // Severity Distribution
        sb.append("<div class='card'><h2>Severity Distribution</h2><table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>");
        for (var e : dist.entrySet()) {
            sb.append("<tr><td class='sev-").append(e.getKey().name()).append("'>")
              .append(e.getKey().name()).append("</td><td>").append(e.getValue()).append("</td></tr>");
        }
        sb.append("</tbody></table></div>");

        // Issues TOC
        sb.append("<div class='card'><h2>Issues (TOC)</h2>");
        if (issues.isEmpty()) {
            sb.append("<div class='sub'>No issues.</div>");
        } else {
            int idx = 1;
            for (VulnResult v : issues) {
                String anchorId = "issue-" + idx + "-" + makeSlug(v.getIssueType().name());
                sb.append("<a href='#").append(anchorId).append("'>#")
                  .append(idx).append(" · [").append(esc(v.getSeverity().name())).append("] ")
                  .append(esc(v.getIssueType().name())).append(" — ")
                  .append(linkifyTrim(v.getUrl(), 80))
                  .append("</a>");
                if (idx < issues.size()) sb.append("<br/>");
                idx++;
            }
        }
        sb.append("</div>");

        // Findings
        sb.append("<div class='card'><h2>Findings</h2><table><thead><tr>")
          .append("<th>#</th>")
          .append("<th class='sortable' data-key='url'>URL</th>")
          .append("<th class='sortable' data-key='type'>Type</th>")
          .append("<th class='sortable' data-key='sev'>Severity</th>")
          .append("<th class='sortable' data-key='risk'>Risk</th>")
          .append("<th>Evidence</th>")
          .append("<th class='sortable' data-key='time'>DetectedAt</th>")
          .append("</tr>")
          // 필터 입력 행
          .append("<tr class='filters'>")
          .append("<th></th>")
          .append("<th><input type='search' placeholder='URL' data-filter='url'></th>")
          .append("<th><input type='search' placeholder='Type' data-filter='type'></th>")
          .append("<th><input type='search' placeholder='Sev' data-filter='sev'></th>")
          .append("<th><input type='search' placeholder='Risk' data-filter='risk' title='예: >=50, <30, 25, 50-80'></th>")
          .append("<th><input type='search' placeholder='Evidence' data-filter='evi'></th>")
          .append("<th><input type='search' placeholder='Time' data-filter='time'></th>")
          .append("</tr></thead><tbody>");
        int i = 1;
        for (VulnResult v : issues) {
            String anchorId = "issue-" + i + "-" + makeSlug(v.getIssueType().name());
            String urlStr   = v.getUrl() == null ? "" : v.getUrl().toString();
            String safeUrl  = esc(urlStr);
            String urlA     = linkify(urlStr);

            // Risk 배지 (null → severity 매핑으로 대체)
            Integer riskScore = v.getRiskScore();
            int rsVal = (riskScore != null) ? riskScore.intValue() : toRisk(v.getSeverity());
            String badgeCls = riskClass(rsVal);
            String riskHtml = "<span class='badge-risk " + badgeCls + "'>" + rsVal + "</span>";

            // Evidence 블럭: 토글 규칙으로 생성
            String evCombined = buildEvidenceBlock(v, evMaxChars, showFullEvidence);
            String evEsc      = esc(evCombined);

            sb.append("<tr id='").append(anchorId).append(">") // keep id semantic
              .append("<td>").append(i++).append("</td>")
              .append("<td class='url' data-col='url'>").append(urlA)
              .append(" <button type='button' class='btn-copy' data-copy='").append(safeUrl).append("'>Copy</button>")
              .append("</td>")
              .append("<td data-col='type'>").append(esc(v.getIssueType().name())).append("</td>")
              .append("<td class='sev-").append(v.getSeverity().name()).append("' data-col='sev'>").append(v.getSeverity().name()).append("</td>")
              .append("<td class='col-risk' data-col='risk' data-val='").append(rsVal).append("'>").append(riskHtml).append("</td>")
              .append("<td data-col='evi'>").append("<div class='ev'><code>").append(evEsc).append("</code></div>")
              .append(" <button class='btn-copy toggle-ev' type='button'>More</button>")
              .append("</td>")
              .append("<td data-col='time'>").append(esc(String.valueOf(v.getDetectedAt()))).append("</td>")
              .append("</tr>");
        }
        if (issues.isEmpty()) {
            sb.append("<tr><td colspan='7' class='sub'>No issues detected.</td></tr>");
        }
        sb.append("</tbody></table></div>");

        // Footer + JS
        sb.append("<div class='sub'>© ").append(Year.now()).append(" WebKillerAI — Non-Destructive Scanner</div>");
        sb.append(HtmlReportTemplates.footer());
        sb.append(clientJs());
        sb.append("</body></html>");

        return sb.toString();
    }

    // ---- Exec Summary header (Avg/95p + Excludes, Max는 title로) ----
    private static String summaryHeaderAvgP95(int avg, int p95, int max, int excludesCount) {
        String avgCls = riskClass(avg);
        String p95Cls = riskClass(p95);
        return """
        <div class="summary-badges">
          <span class="badge-risk %s" title="평균(반올림)">Avg <b>%d</b></span>
          <span class="badge-risk %s" title="Max: %d">95p <b>%d</b></span>
          <span class="chip chip-excludes">Excludes: <b>%d</b> rules</span>
        </div>
        """.formatted(avgCls, avg, p95Cls, max, p95, excludesCount);
    }

    // ---- client-side helpers (링크/텍스트) ----

    private static String linkify(Object url) {
        String u = url == null ? "" : String.valueOf(url).trim();
        if (u.isBlank()) return "";
        String lu = u.toLowerCase(java.util.Locale.ROOT);
        if (!(lu.startsWith("http://") || lu.startsWith("https://"))) {
            return esc(u); // http/https 외는 텍스트만
        }
        String escText = esc(u);
        String escHref = esc(u);
        return "<a href=\"" + escHref + "\" rel=\"noopener noreferrer\" target=\"_blank\">" + escText + "</a>";
    }

    private static String linkifyTrim(Object url, int maxLen) {
        String u = url == null ? "" : String.valueOf(url);
        if (u.isBlank()) return "";
        String text = trim(u, Math.max(8, maxLen));
        String escText = esc(text);
        String escHref = esc(u);
        return "<a href=\"" + escHref + "\" rel=\"noopener noreferrer\" target=\"_blank\">" + escText + "</a>";
    }

    private static String esc(Object o) { return esc(o == null ? "" : String.valueOf(o)); }

    // ---------------- helpers ----------------

    private static void kv(StringBuilder sb, String k, String v) {
        sb.append("<div class='card'><div class='sub'>").append(esc(k)).append("</div><div><b>")
          .append(esc(v)).append("</b></div></div>");
    }

    private static void kvHtml(StringBuilder sb, String k, String html) {
        sb.append("<div class='card'><div class='sub'>").append(esc(k)).append("</div><div><b>")
          .append(html).append("</b></div></div>");
    }

    private static String riskBadge(int score, String cls){
        return "<span class='badge-risk " + cls + "'>" + score + "</span>";
    }

    private static String riskClass(int score){
        return (score <= 24) ? "badge-low"
             : (score <= 49) ? "badge-med"
             : (score <= 74) ? "badge-high"
             : "badge-crit";
    }

    private static String extractHost(String target) {
        try {
            var u = URI.create(target);
            String h = u.getHost();
            return (h == null ? target : h).toLowerCase(Locale.ROOT);
        } catch (Exception e) { return "unknown"; }
    }

    private static String makeSlug(String s) {
        if (s == null) return "unknown";
        String slug = s.toLowerCase(Locale.ROOT)
                .replaceFirst("^https?://", "")
                .replaceAll("[^a-z0-9._-]+", "-");
        if (slug.isBlank()) slug = "target";
        return slug;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'", "&#39;");
    }

    private static String trim(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    /** Severity → Risk Score(0..100) 간단 매핑 (null fallback용) */
    private static int toRisk(Severity s){
        if (s == null) return 0;
        switch (s){
            case INFO: return 10;
            case LOW: return 25;
            case MEDIUM: return 50;
            case HIGH: return 75;
            case CRITICAL: return 90;
            default: return 0;
        }
    }

    /** 전체 리스크 점수(0~100): JSON 계산식과 일치 */
    private static int calcRiskScore(int h,int m,int l,int total){
        int sev = h*90 + m*60 + l*30;
        int policy = (h+m)>0 ? 20 : 0;
        int count = Math.min(10, total*2);
        int score = (int)Math.round(0.55*(sev/Math.max(1.0,total)) + 0.15*count + 0.30*policy);
        return Math.max(0, Math.min(100, score));
    }

    /** 다양한 ScanConfig 변형을 반영: excludePaths 카운트 리플렉션 안전 조회 */
    private static int excludeCountFromConfig(ScanConfig cfg){
        try {
            Method m = cfg.getClass().getMethod("getExcludePaths");
            Object v = m.invoke(cfg);
            if (v instanceof Collection) return ((Collection<?>) v).size();
        } catch (Exception ignore) {}
        try {
            Method m = cfg.getClass().getMethod("getCrawler");
            Object crawler = m.invoke(cfg);
            if (crawler != null) {
                try {
                    Method m2 = crawler.getClass().getMethod("getExcludePaths");
                    Object v2 = m2.invoke(crawler);
                    if (v2 instanceof Collection) return ((Collection<?>) v2).size();
                } catch (Exception ignore) {}
            }
        } catch (Exception ignore) {}
        return 0;
    }

    private static int sysInt(String key, int def) {
        try { return Integer.parseInt(System.getProperty(key, String.valueOf(def)).trim()); }
        catch (Exception e) { return def; }
    }

    /** Evidence 칸에 넣을 문자열(요청 라인 + 스니펫) 생성 — 토글 적용 */
    private static String buildEvidenceBlock(VulnResult v, int maxChars, boolean showFull) {
        String req = v.getRequestLine();
        String sn  = v.getEvidenceSnippet();
        if (sn == null || sn.isBlank()) sn = v.getEvidence();

        String joined;
        if (showFull) {
            joined = (req == null || req.isBlank()) ? safe(sn) : (req + "\n" + safe(sn));
        } else {
            joined = safe(v.getEvidence()); // SAFE 모드 기본값: 최소 evidence만
        }
        return trim(joined, Math.max(32, maxChars));
    }

    private static String safe(String s){ return s == null ? "" : s; }

    /** 시스템 프로퍼티 + FeatureMatrix 기반 Evidence 표시 토글 */
    private static boolean showEvidenceDetails(ScanConfig cfg) {
        String p = System.getProperty("wk.report.showEvidenceDetails", "")
                         .trim().toLowerCase(java.util.Locale.ROOT);
        if (p.equals("on") || p.equals("true") || p.equals("1"))  return true;
        if (p.equals("off")|| p.equals("false")|| p.equals("0"))  return false;
        // 기본: 해당 모드에서 액티브가 하나라도 켜져 있으면 상세 evidence 표시
        return FeatureMatrix.isAnyActive(cfg.getMode());
    }

    /** 클라이언트 스크립트: 정렬/복사/증거 펼치기/퀵 필터 */
    private static String clientJs() {
        return """
        <script>
        (function(){
          // ===== Sorting =====
          function weightSev(s){
            switch((s||"").trim().toUpperCase()){
              case "CRITICAL": return 4;
              case "HIGH": return 3;
              case "MEDIUM": return 2;
              case "LOW": return 1;
              case "INFO": return 0;
              default: return -1;
            }
          }
          document.querySelectorAll('thead th.sortable').forEach(function(th){
            th.addEventListener('click', function(){
              var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
              var tbody = th.closest('table').querySelector('tbody');
              var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
              var key = th.dataset.key || 'text';
              var dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
              // reset indicators
              th.parentNode.querySelectorAll('th').forEach(function(x){ x.classList.remove('sorted-asc','sorted-desc'); x.removeAttribute('data-dir'); });
              th.dataset.dir = dir;
              th.classList.add(dir === 'asc' ? 'sorted-asc' : 'sorted-desc');

              rows.sort(function(a,b){
                var sign = (dir === 'asc') ? 1 : -1;

                // risk: data-val(정수) 기준 정렬, 없으면 항상 하단
                if (key === 'risk') {
                  var va = parseInt(a.children[idx].getAttribute('data-val') || '-1', 10);
                  var vb = parseInt(b.children[idx].getAttribute('data-val') || '-1', 10);
                  if (isNaN(va) || va < 0) va = (dir === 'asc') ? 1e9 : -1e9;
                  if (isNaN(vb) || vb < 0) vb = (dir === 'asc') ? 1e9 : -1e9;
                  return sign * (va - vb);
                }

                // severity: 가중치 기반
                if (key === 'sev') {
                  var ta = (a.children[idx].innerText || '').trim();
                  var tb = (b.children[idx].innerText || '').trim();
                  return sign * (weightSev(ta) - weightSev(tb));
                }

                // 기본: 텍스트 비교
                var ta = (a.children[idx].innerText || '').trim();
                var tb = (b.children[idx].innerText || '').trim();
                return sign * ta.localeCompare(tb);
              });
              rows.forEach(function(r){ tbody.appendChild(r); });
            });
          });

          // ===== Copy & Evidence Toggle =====
          document.addEventListener('click', function(e){
            var copyBtn = e.target.closest('.btn-copy');
            if (copyBtn && !copyBtn.classList.contains('toggle-ev')) {
              var text = copyBtn.getAttribute('data-copy') || '';
              if (text && navigator.clipboard) {
                navigator.clipboard.writeText(text).then(function(){
                  var prev = copyBtn.textContent;
                  copyBtn.textContent = 'Copied';
                  setTimeout(function(){ copyBtn.textContent = prev || 'Copy'; }, 900);
                });
              }
            }
            var tgl = e.target.closest('.toggle-ev');
            if (tgl) {
              var ev = tgl.previousElementSibling; // .ev
              if (ev) {
                ev.classList.toggle('open');
                tgl.textContent = ev.classList.contains('open') ? 'Less' : 'More';
              }
            }
          });

          // ===== Quick Filters =====
          (function(){
            var filtersRow = document.querySelector('table thead tr.filters');
            if (!filtersRow) return;
            var table = filtersRow.closest('table');
            var inputs = table.querySelectorAll('tr.filters input[data-filter]');
            var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));

            function getVal(tr, key){
              if (key === 'risk') {
                var td = tr.querySelector("td[data-col='risk']");
                var val = parseInt(td && td.getAttribute('data-val') || '-1', 10);
                return isNaN(val) ? -1 : val;
              }
              var td2 = tr.querySelector("td[data-col='"+key+"']");
              return (td2 && td2.innerText || '').toLowerCase();
            }

            function parseRiskQuery(txt, v){
              var s = (txt||'').trim().toLowerCase();
              var m;
              if (m = s.match(/^(>=|<=|>|<)\\s*(\\d{1,3})$/)) {
                var n = parseInt(m[2],10);
                if (m[1] === '>')  return v >  n;
                if (m[1] === '>=') return v >= n;
                if (m[1] === '<')  return v <  n;
                if (m[1] === '<=') return v <= n;
              }
              if (m = s.match(/^(\\d{1,3})\\s*-\\s*(\\d{1,3})$/)) {
                var a = parseInt(m[1],10), b = parseInt(m[2],10);
                var lo = Math.min(a,b), hi = Math.max(a,b);
                return v >= lo && v <= hi;
              }
              if (m = s.match(/^(\\d{1,3})$/)) {
                return v === parseInt(m[1],10);
              }
              return String(v).includes(s);
            }

            function debounce(fn, ms){ var t; return function(){ clearTimeout(t); var args=arguments; t=setTimeout(function(){ fn.apply(null,args); }, ms); }; }
            var apply = debounce(function(){
              var q = {};
              inputs.forEach(function(i){ q[i.dataset.filter] = (i.value || '').trim().toLowerCase(); });
              rows.forEach(function(tr){
                var show = true;
                ['url','type','sev','evi','time'].forEach(function(k){
                  if (!show || !q[k]) return;
                  show = getVal(tr,k).indexOf(q[k]) !== -1;
                });
                if (show && q['risk']) {
                  var v = getVal(tr,'risk');
                  show = parseRiskQuery(q['risk'], v);
                }
                tr.style.display = show ? '' : 'none';
              });
            }, 200);

            inputs.forEach(function(i){ i.addEventListener('input', apply); });
          })();

        })();
        </script>
        """;
    }
}
