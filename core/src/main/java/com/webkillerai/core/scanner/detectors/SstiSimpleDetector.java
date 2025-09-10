package com.webkillerai.core.scanner.detectors;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import com.webkillerai.core.util.UrlParamUtil;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.*;

public class SstiSimpleDetector {

    private static final String TAG = "WKAI";
    private static final String EXPECT = "49" + TAG;

    private static final List<String> PAYLOADS = List.of(
            "{{7*7}}" + TAG,   // Jinja2류
            "${7*7}" + TAG     // EL/SpEL류
    );

    private static final String[] ERROR_TOKENS = {
            "TemplateSyntaxError", "jinja2.exceptions",
            "UndefinedError", "VariableNotFound",
            "org.thymeleaf", "ELException", "javax.el.ELException",
            "freemarker.template.TemplateException",
            "VelocityException", "OGNL", "SpEL", "ParseException"
    };

    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base) {
        String param = pickParam(base, cfg.getXssParamHints());
        return detect(engine, cfg, base, param);
    }

    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base, String forceParam) {
        if (cfg.getMode() != Mode.SAFE_PLUS && cfg.getMode() != Mode.AGGRESSIVE_LITE) return Optional.empty();
        String param = (forceParam == null || forceParam.isBlank()) ? "q" : forceParam;

        for (String payload : PAYLOADS) {
            // 1) 표준 방식: 유틸로 추가(별표가 %2A로 인코딩될 수 있음)
            Optional<VulnResult> r1 = tryOnce(engine, base, param, payload, true);
            if (r1.isPresent()) return r1;

            // 2) 보정 방식: { } $ 만 %인코딩, *는 그대로 두고 수동으로 쿼리 붙이기
            Optional<VulnResult> r2 = tryOnce(engine, base, param, payload, false);
            if (r2.isPresent()) return r2;
        }
        return Optional.empty();
    }

    private Optional<VulnResult> tryOnce(ProbeEngine engine, URI base, String param, String payload, boolean useUtil) {
        try {
            URI target = useUtil
                    ? UrlParamUtil.withAddedParams(base, Map.of(param, List.of(payload)))
                    : appendQueryManually(base, param, encodeCurlyAndDollarOnly(payload));

            HttpResponse<String> rsp = engine.get(target, Map.of("Accept","text/html,application/xhtml+xml"));
            String body = rsp.body();
            if (body == null || body.isEmpty()) return Optional.empty();

            // 평가 결과(49WKAI) → HIGH
            if (body.contains(EXPECT)) {
                return Optional.of(buildResult(Severity.HIGH, target, body, EXPECT,
                        "Server-Side Template Injection: expression evaluated in response."));
            }
            // 템플릿 엔진 에러 노출 → MEDIUM
            String err = matchError(body);
            if (err != null) {
                return Optional.of(buildResult(Severity.MEDIUM, target, body, err,
                        "Possible SSTI: template engine error revealed after injection."));
            }
        } catch (Exception ignore) { }
        return Optional.empty();
    }

    private VulnResult buildResult(Severity sev, URI target, String body, String marker, String desc) {
        String reqLine = ProbeEngine.requestLine("GET", target);
        String snippet = ProbeEngine.snippetAround(body, marker, 80);
        String evidence = reqLine + "\n" + snippet;
        return VulnResult.builder()
                .issueType(IssueType.SSTI)
                .severity(sev)
                .url(target)
                .description(desc)
                .requestLine(reqLine)
                .evidenceSnippet(snippet)
                .evidence(evidence)
                .build();
    }

    private String matchError(String body) {
        String l = body.toLowerCase(Locale.ROOT);
        for (String s : ERROR_TOKENS) {
            if (l.contains(s.toLowerCase(Locale.ROOT))) return s;
        }
        return null;
    }

    private String pickParam(URI uri, List<String> hints) {
        List<String> safeHints = (hints == null || hints.isEmpty())
                ? List.of("q","search","s","query","keyword","name","user")
                : hints;
        String q = uri.getRawQuery();
        if (q != null && !q.isEmpty()) {
            for (String h : safeHints) {
                if (q.contains(h + "=")) return h;
            }
        }
        return safeHints.get(0);
    }

    // --- 수동 인코딩/쿼리 부착 헬퍼들 ---

    /** {, }, $ 만 퍼센트 인코딩. *는 그대로 둔다(테스트 서버 패턴과 일치시키기 위함). */
    private static String encodeCurlyAndDollarOnly(String s) {
        if (s == null) return "";
        return s.replace("{", "%7B")
                .replace("}", "%7D")
                .replace("$", "%24");
    }

    private static URI appendQueryManually(URI base, String key, String valueAlreadyEncoded) {
        String raw = base.toString();
        String delim = (base.getRawQuery() == null) ? "?" : "&";
        String newUrl = raw + delim + key + "=" + valueAlreadyEncoded;
        return URI.create(newUrl);
    }
}
