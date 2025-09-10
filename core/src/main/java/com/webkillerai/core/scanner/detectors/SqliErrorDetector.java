package com.webkillerai.core.scanner.detectors;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import com.webkillerai.core.util.UrlParamUtil;
import com.webkillerai.core.model.Mode;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.*;

/** 에러 기반(SQL 오류 메시지) SQLi 최소 탐지기 */
public class SqliErrorDetector {

    private static final String INJECT = "'";

    // 대표 에러 시그니처(보수적)
    private static final String[] SIGNS = {
            // 공통/프레임워크
            "SQLSTATE[", "JDBCException", "HibernateException",
            // MySQL/MariaDB
            "You have an error in your SQL", "SQL syntax", "MariaDB server version",
            // PostgreSQL
            "ERROR: syntax error at or near", "PG::SyntaxError",
            // Oracle
            "ORA-00933", "ORA-00904", "ORA-01756", "ORA-00936",
            // SQL Server
            "Unclosed quotation mark", "Incorrect syntax near",
            // SQLite
            "SQLite3::SQLException", "unrecognized token"
    };

    /** 힌트 기반(선택) */
    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base) {
        String param = pickParam(base, cfg.getSqliParamHints()).orElse("id");
        return detect(engine, cfg, base, param);
    }

    /** Orchestrator용 강제 파라미터 버전 (부적합하면 스스로 교정) */
    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base, String forceParam) {
        // SAFE_PLUS 에서만 동작
        if (cfg.getMode() != Mode.SAFE_PLUS) return Optional.empty();

        String param = chooseBestParam(forceParam, base, cfg.getSqliParamHints());

        // ★ 주입/프로브 시엔 "선두 오버라이드"가 더 안전 (서버가 첫 값만 읽는 경우 대비)
        URI target = UrlParamUtil.withParamOverrideFirst(base, param, INJECT);

        try {
            HttpResponse<String> rsp = engine.get(target, Map.of("Accept","text/html,application/xhtml+xml"));
            String body = rsp.body();
            if (body == null || body.isEmpty()) return Optional.empty();

            String hit = match(body);
            if (hit == null) return Optional.empty();

            String reqLine = ProbeEngine.requestLine("GET", target);
            String snippet = ProbeEngine.snippetAround(body, hit, 80);
            String evidence = reqLine + "\n" + snippet; // 표준화: 요청 라인 + 스니펫

            VulnResult vr = VulnResult.builder()
                    .issueType(IssueType.SQLI_PATTERN) // 오류 기반 시그니처
                    .severity(Severity.HIGH)
                    .url(target)
                    .description("DB error signature detected after single-quote injection")
                    .requestLine(reqLine)
                    .evidenceSnippet(snippet)
                    .evidence(evidence)
                    .build();

            return Optional.of(vr);
        } catch (Exception ignore) { }
        return Optional.empty();
    }

    // ---------- 내부 헬퍼 ----------

    private String match(String body) {
        String l = body.toLowerCase(Locale.ROOT);
        for (String s : SIGNS) {
            if (l.contains(s.toLowerCase(Locale.ROOT))) return s;
        }
        return null;
    }

    private Optional<String> pickParam(URI uri, List<String> hints) {
        List<String> safeHints = (hints == null || hints.isEmpty())
                ? List.of("id","uid","user","no","prod","cat","page")
                : hints;
        String q = uri.getRawQuery();
        if (q != null && !q.isEmpty()) {
            String lq = q.toLowerCase(Locale.ROOT);
            for (String h : safeHints) {
                if (lq.contains(h.toLowerCase(Locale.ROOT) + "=")) return Optional.of(h);
            }
        }
        return Optional.of(safeHints.get(0));
    }

    /** forceParam이 힌트에 없거나 부적절하면 힌트/쿼리 기반으로 보정 */
    private String chooseBestParam(String forceParam, URI base, List<String> hints) {
        List<String> safeHints = (hints == null || hints.isEmpty())
                ? List.of("id","uid","user","no","prod","cat","page")
                : hints;

        // 1) 강제 키가 힌트에 포함되면 그대로 사용
        if (forceParam != null && !forceParam.isBlank()) {
            for (String h : safeHints) {
                if (h.equalsIgnoreCase(forceParam)) return h;
            }
        }

        // 2) URL 쿼리에 힌트 키가 있으면 그중 첫 번째 사용
        String q = base.getRawQuery();
        if (q != null && !q.isBlank()) {
            String lq = q.toLowerCase(Locale.ROOT);
            for (String h : safeHints) {
                if (lq.contains(h.toLowerCase(Locale.ROOT) + "=")) return h;
            }
        }

        // 3) 그 외에는 첫 힌트(id) 사용
        return safeHints.get(0);
    }
}
