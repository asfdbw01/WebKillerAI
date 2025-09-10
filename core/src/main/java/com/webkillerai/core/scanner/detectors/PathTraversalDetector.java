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
import java.nio.charset.StandardCharsets;
import java.util.*;

public class PathTraversalDetector {

    private static final List<String> HINTS = List.of(
            "file","path","page","template","view","include","doc","download","img","name"
    );

    private static final String UNIX_PAYLOAD = "../../../../../etc/passwd";
    private static final String WIN_PAYLOAD  = "..\\..\\..\\windows\\win.ini";

    private static final String[] SIGNS = {
            "root:x:0:0:",
            "[fonts]", "[extensions]"
    };

    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base) {
        String param = pickParam(base).orElse("file");
        return detect(engine, cfg, base, param);
    }

    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI base, String forceParam) {
        if (cfg.getMode() != Mode.SAFE_PLUS && cfg.getMode() != Mode.AGGRESSIVE_LITE) return Optional.empty();

        String param = (forceParam == null || forceParam.isBlank()) ? "file" : forceParam;

        // 1) 기본 페이로드 2종
        List<String> rawPayloads = List.of(UNIX_PAYLOAD, WIN_PAYLOAD);

        // 2) 각 페이로드에 대해 (a) UrlParamUtil 사용, (b) 최소 인코딩 후 raw-append 둘 다 시도
        for (String payload : rawPayloads) {
            // (a) 일반적인 추가(라이브러리 인코딩에 맡김)
            try {
                URI u1 = UrlParamUtil.withAddedParams(base, Map.of(param, List.of(payload)));
                if (probeOnce(engine, u1)) {
                    return buildResult(engine, u1);
                }
            } catch (Exception ignore) {}

            // (b) 최소 인코딩(슬래시/백슬래시만 퍼센트 인코딩) 후, 쿼리에 직접 붙여 전송
            try {
                String minimallyEncoded = minimalSlashEncode(payload);
                URI u2 = appendQueryRaw(base, param, minimallyEncoded);
                if (probeOnce(engine, u2)) {
                    return buildResult(engine, u2);
                }
            } catch (Exception ignore) {}
        }

        return Optional.empty();
    }

    /** 한 번 전송해서 시그니처 매칭되면 true */
    private boolean probeOnce(ProbeEngine engine, URI target) throws Exception {
        HttpResponse<String> rsp = engine.get(target,
                Map.of("Accept","text/plain,text/html,application/xhtml+xml"));
        String body = rsp.body();
        if (body == null || body.isEmpty()) return false;
        return match(body) != null;
    }

    private Optional<VulnResult> buildResult(ProbeEngine engine, URI target) throws Exception {
        HttpResponse<String> rsp = engine.get(target,
                Map.of("Accept","text/plain,text/html,application/xhtml+xml"));
        String body = rsp.body();
        String hit = match(body);
        if (hit == null) return Optional.empty();

        String reqLine = ProbeEngine.requestLine("GET", target);
        String snippet = ProbeEngine.snippetAround(body, hit, 80);
        String evidence = reqLine + "\n" + snippet;

        VulnResult vr = VulnResult.builder()
                .issueType(IssueType.PATH_TRAVERSAL)
                .severity(Severity.HIGH)
                .url(target)
                .description("Path traversal via parameter (evidence from included file).")
                .requestLine(reqLine)
                .evidenceSnippet(snippet)
                .evidence(evidence)
                .build();
        return Optional.of(vr);
    }

    private String match(String body) {
        String l = body.toLowerCase(Locale.ROOT);
        for (String s : SIGNS) {
            if (l.contains(s.toLowerCase(Locale.ROOT))) return s;
        }
        return null;
    }

    private Optional<String> pickParam(URI uri) {
        String q = uri.getRawQuery();
        if (q != null && !q.isEmpty()) {
            for (String h : HINTS) {
                if (q.contains(h + "=")) return Optional.of(h);
            }
        }
        return Optional.of("file");
    }

    /** 최소 인코딩: 슬래시/백슬래시만 퍼센트 인코딩, 점은 그대로 유지 (서버의 '..%2F' 패턴과 호환) */
    private static String minimalSlashEncode(String s) {
        if (s == null) return "";
        String out = s.replace("/", "%2F")
                      .replace("\\", "%5C");
        // 스페이스 등 다른 문자가 섞이면 필요 최소한만 추가로 인코딩
        // (테스트 데이터엔 없지만 안전하게 만약의 상황 대비)
        StringBuilder sb = new StringBuilder(out.length()+8);
        for (int i=0;i<out.length();i++) {
            char c = out.charAt(i);
            if (c == ' ') sb.append("%20");
            else sb.append(c);
        }
        return sb.toString();
    }

    /** 쿼리에 raw 값 그대로 붙이는 간단 조립기 (추가 인코딩 방지) */
    private static URI appendQueryRaw(URI base, String key, String rawValue) {
        String prefix = (base.getRawQuery() == null || base.getRawQuery().isEmpty()) ? "?" : "&";
        String raw = key + "=" + rawValue;
        String s = base.toString() + prefix + raw;
        return URI.create(s);
    }
}
