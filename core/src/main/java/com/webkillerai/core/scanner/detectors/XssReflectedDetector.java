package com.webkillerai.core.scanner.detectors;

import com.webkillerai.core.config.FeatureMatrix;
import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Mode;          // 최상위 Mode import
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import com.webkillerai.core.util.UrlParamUtil;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Reflected XSS (무해 토큰) 탐지:
 *  - 해당 파라미터가 이미 있든 없든, 값을 선두에서 덮어쓰는 방식으로 주입
 *  - 반사되고 이스케이프되지 않은 경우 컨텍스트 기반 Severity 산정
 */
public class XssReflectedDetector {

    private static final String TOKEN = "WKAI_XSS_TOKEN_<>";
    private static final List<String> SAFE_PAYLOADS = List.of(TOKEN);

    /** 힌트 기반(선택) */
    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base) {
        String param = pickParam(base, cfg.getXssParamHints()).orElse("q");
        return detect(engine, cfg, base, param);
    }

    /** Orchestrator에서 파라미터를 지정해 호출 */
    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base, String forceParam) {
        // FeatureMatrix에 맞게 게이트 (현재는 SAFE_PLUS에서만)
        Mode mode = cfg.getMode();
        if (!FeatureMatrix.activeXssReflected(mode)) return Optional.empty();

        String param = (forceParam == null || forceParam.isBlank()) ? "q" : forceParam;

        try {
            // 동일 키 모두 제거하고 선두에 덮어쓰기 (서버가 첫 값만 읽는 케이스 대응)
            URI target = UrlParamUtil.withParamOverrideFirst(base, param, SAFE_PAYLOADS.get(0));

            HttpResponse<String> rsp = engine.get(target, java.util.Map.of("Accept","text/html,application/xhtml+xml"));
            String body = rsp.body();
            if (body == null || body.isEmpty()) return Optional.empty();
            if (!body.contains(TOKEN)) return Optional.empty();   // 반사 없음
            if (isEscaped(body, TOKEN)) return Optional.empty();  // 이스케이프됨

            Severity sev = contextSeverity(body, TOKEN);

            String reqLine = ProbeEngine.requestLine("GET", target);
            String snippet = ProbeEngine.snippetAround(body, TOKEN, 80);
            String evidence = reqLine + "\n" + snippet;

            VulnResult vr = VulnResult.builder()
                    .issueType(IssueType.XSS_REFLECTED)
                    .severity(sev)
                    .url(target)
                    .description(sev == Severity.HIGH
                            ? "Token reflected into HTML without escaping (text/HTML context)."
                            : "Token reflected into attribute-like context; potential XSS depending on sinks.")
                    .requestLine(reqLine)
                    .evidenceSnippet(snippet)
                    .evidence(evidence)
                    .build();

            return Optional.of(vr);
        } catch (Exception ignore) { }
        return Optional.empty();
    }

    private boolean isEscaped(String body, String token) {
        int idx = body.indexOf(token);
        if (idx < 0) return true;
        String around = ProbeEngine.snippetAround(body, token, 8);
        return around.contains("&lt;") || around.contains("&gt;");
    }

    private Severity contextSeverity(String body, String token) {
        String around = ProbeEngine.snippetAround(body, token, 64);
        boolean attrDouble = around.matches("(?is).*\\b[A-Za-z0-9_-]+\\s*=\\s*\"[^\"]*" + Pattern.quote(token) + "[^\"]*\".*");
        boolean attrSingle = around.matches("(?is).*\\b[A-Za-z0-9_-]+\\s*=\\s*'[^']*" + Pattern.quote(token) + "[^']*'.*");
        return (attrDouble || attrSingle) ? Severity.MEDIUM : Severity.HIGH;
    }

    private Optional<String> pickParam(URI uri, List<String> hints) {
        String q = uri.getRawQuery();
        List<String> safeHints = (hints == null || hints.isEmpty())
                ? List.of("q","search","s","query","keyword")
                : hints;
        if (q != null && !q.isEmpty()) {
            String lq = q.toLowerCase(Locale.ROOT);
            for (String h : safeHints) {
                if (lq.contains(h.toLowerCase(Locale.ROOT) + "=")) return Optional.of(h);
            }
        }
        return Optional.of(safeHints.get(0));
    }
}
