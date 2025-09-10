package com.webkillerai.core.service.export;

final class HtmlReportTemplates {
    private HtmlReportTemplates() {}

    static String css() {
        return """
        <style>
        /* ===== Dark (default) ===== */
        :root{
          --bg:#0f172a; --fg:#e5e7eb; --muted:#94a3b8;
          --card:#0b1220; --bd:#2a3343; --row:#0e1624; --chip:#1f2937; --barbg:#1f2937;
          --hi:#ef4444; --crit:#dc2626; --med:#f59e0b; --low:#22c55e; --info:#60a5fa;
          --link:#60a5fa; --linkv:#a78bfa;
          /* ★ 대비 강화: code / button 토큰 */
          --code-bg:#111827; --code-fg:#e5e7eb;
          --btn-bg:#1f2937; --btn-bd:#334155; --btn-fg:#e5e7eb; --btn-bg-h:#374151;
        }
        /* ===== Light ===== */
        @media (prefers-color-scheme: light){
          :root{
            --bg:#ffffff; --fg:#0f172a; --muted:#475569;
            --card:#ffffff; --bd:#e2e8f0; --row:#f8fafc; --chip:#e5e7eb; --barbg:#e5e7eb;
            --hi:#dc2626; --crit:#b91c1c; --med:#d97706; --low:#16a34a; --info:#2563eb;
            --link:#2563eb; --linkv:#7c3aed;
            --code-bg:#f3f4f6; --code-fg:#111827;
            --btn-bg:#f8fafc; --btn-bd:#cbd5e1; --btn-fg:#0f172a; --btn-bg-h:#e5e7eb;
          }
        }

        /* Base */
        html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Noto Sans',sans-serif}
        a{color:var(--link);text-decoration:underline}
        a:visited{color:var(--linkv)}
        .muted{color:var(--muted)}
        .wrap{padding:12px 24px 48px}

        /* Header */
        header{padding:16px 24px;border-bottom:1px solid var(--bd);background:var(--bg)}
        header h1{font-size:20px;margin:0 0 6px}

        /* Cards / chips */
        .card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;margin:12px 0;box-shadow:0 1px 2px rgba(0,0,0,.12)}
        .chips{margin:.25rem 0 .25rem}
        .chip{display:inline-block;padding:.28rem .6rem;border-radius:.6rem;background:var(--chip);margin-right:.35rem;font-weight:700}

        /* Severity text colors (table body) */
        .sev-CRITICAL{color:var(--crit);font-weight:700}
        .sev-HIGH{color:var(--hi);font-weight:700}
        .sev-MEDIUM{color:var(--med);font-weight:700}
        .sev-LOW{color:var(--low);font-weight:700}
        .sev-INFO{color:var(--info)}

        /* Chip variants (high contrast) */
        .chip.sev-CRITICAL{background:var(--crit);color:#fff}
        .chip.sev-HIGH{background:var(--hi);color:#fff}
        .chip.sev-MEDIUM{background:var(--med);color:#111}
        .chip.sev-LOW{background:var(--low);color:#0b1220}

        /* === Risk badge (per-row) === */
        .badge-risk{display:inline-block;padding:.18rem .5rem;border-radius:.5rem;font-weight:600}
        .badge-low {background:var(--low);  color:#0b1220}
        .badge-med {background:var(--med);  color:#111}
        .badge-high{background:var(--hi);   color:#fff}
        .badge-crit{background:var(--crit); color:#fff}
        /* Risk column alignment */
        td.col-risk{text-align:right}

        /* Summary bar */
        .bar{height:14px;background:var(--barbg);border-radius:7px;overflow:hidden;margin:.5rem 0 .9rem;display:flex}
        .bar>i{display:block;height:100%}

        /* Table */
        table{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--bd);border-radius:12px;overflow:hidden;background:var(--card)}
        thead th{background:var(--card);border-bottom:1px solid var(--bd);padding:10px;text-align:left;font-weight:800;letter-spacing:.2px}
        tbody td{padding:10px;border-bottom:1px solid var(--bd)}
        tbody tr:nth-child(even){background:var(--row)}
        tbody tr:hover{filter:brightness(1.08)}
        .url{word-break:break-all}
        .url a{word-break:break-all}

        /* Toolbar / buttons / sort / evidence */
        .toolbar{position:sticky;top:0;background:var(--bg);padding:8px 0;margin:6px 0 8px;border-bottom:1px dashed var(--bd);display:flex;gap:8px;align-items:center;z-index:2}
        .toolbar input[type="search"]{flex:1;min-width:160px;padding:6px 8px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg)}
        .toolbar .btn{padding:6px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg);cursor:pointer}
        .btn-copy{margin-left:6px;font-size:12px;padding:4px 6px;border:1px solid var(--btn-bd);border-radius:6px;background:var(--btn-bg);color:var(--btn-fg);cursor:pointer}
        .btn-copy:hover{background:var(--btn-bg-h)}
        thead th.sortable{cursor:pointer;user-select:none}
        thead th.sorted-asc::after{content:" \\25B2";opacity:.7}
        thead th.sorted-desc::after{content:" \\25BC";opacity:.7}
        /* Evidence clamp */
        .ev{max-height:3.2em;overflow:hidden}
        .ev.open{max-height:none}
        /* 긴 문자열 줄바꿈/접기 가독성 ↑ */
        .ev code{white-space:pre-wrap; word-break:break-word}

        /* Evidence code contrast */
        code{background:var(--code-bg); color:var(--code-fg); padding:2px 6px; border-radius:6px}

        /* === Executive Summary (Avg/Max/Excludes) === */
        .summary-header{display:flex;gap:.5rem;align-items:center;margin:6px 0 10px}
        .badge{display:inline-flex;align-items:center;padding:.2rem .5rem;border-radius:.5rem;font-weight:700;border:1px solid var(--bd);background:var(--card)}
        .badge-kpi{background:var(--chip);color:var(--fg)}
        @media (prefers-color-scheme: light){
          .badge{border-color:var(--bd);background:var(--card)}
          .badge-kpi{background:var(--chip)}
        }

        /* Print */
        @media print{
          .toolbar,.btn,.btn-copy{display:none}
          a{text-decoration:none;color:#000}
          header{border:none}
          .card{box-shadow:none}
        }
        </style>
        """;
    }

    static String header(String title, String subtitle) {
        return """
        <header id="top">
          <h1>%s</h1>
          <div class="muted">%s</div>
        </header>
        <div class="wrap">
        """.formatted(esc(title), esc(subtitle));
    }

    /**
     * NEW: Executive Summary (Risk Avg/Max + Excludes 칩)
     * - header(...) 바로 다음에 렌더링하도록 사용
     */
    static String summaryHeader(double riskAvg, int riskMax, int excludesCount) {
        String avg = String.format(java.util.Locale.US, "%.1f", riskAvg);
        return """
        <div class="summary-header">
          <span class="badge badge-kpi" title="Average risk across issues">Risk Avg <strong>%s</strong>/100</span>
          <span class="badge badge-kpi" title="Maximum risk among issues">Max <strong>%d</strong>/100</span>
          <span class="chip" title="Number of exclusion rules applied">Excludes: <strong>%d</strong> rules</span>
        </div>
        """.formatted(avg, riskMax, excludesCount);
    }

    static String summaryBar(int high, int med, int low) {
        int total = Math.max(0, high) + Math.max(0, med) + Math.max(0, low);
        double pH = total==0?0:(high*100.0/total);
        double pM = total==0?0:(med *100.0/total);
        double pL = Math.max(0, 100.0 - pH - pM);

        return """
        <div class='chips'>
          <span class='chip sev-HIGH'   title='HIGH'>HIGH: %d</span>
          <span class='chip sev-MEDIUM' title='MEDIUM'>MED: %d</span>
          <span class='chip sev-LOW'    title='LOW'>LOW: %d</span>
        </div>
        <div class='bar' title='HIGH %.0f%% · MED %.0f%% · LOW %.0f%%'>
          <i style='width:%.0f%%;background:var(--hi)'></i>
          <i style='width:%.0f%%;background:var(--med)'></i>
          <i style='width:%.0f%%;background:var(--low)'></i>
        </div>
        """.formatted(high, med, low, pH, pM, pL, pH, pM, pL);
    }

    static String footer() {
        return """
        <footer class='muted' style='margin-top:16px'>
          <a href="#top" style="text-decoration:none">▲ Back to top</a>
        </footer>
        </div>
        """;
    }

    private static String esc(String s){
        if(s==null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'","&#39;");
    }
}
