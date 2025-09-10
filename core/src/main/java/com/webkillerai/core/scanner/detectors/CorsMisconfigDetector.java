package com.webkillerai.core.scanner.detectors;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.Optional;

/**
 * CORS Misconfiguration detector
 * - Flags the classic unsafe combo: ACAO="*" together with ACAC=true (credentials allowed).
 * - Orchestrator/FeatureMatrix is responsible for mode gating; this detector contains no mode checks.
 */
public class CorsMisconfigDetector {

    /** Probe with a safe, non-origin domain and inspect preflight response headers. */
    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI url) {
        final String origin = "https://wkai.example"; // safe synthetic origin
        try {
            HttpResponse<String> rsp = engine.preflight(url, origin, "GET");

            String acao = header(rsp, "Access-Control-Allow-Origin");
            String acac = header(rsp, "Access-Control-Allow-Credentials");

            if ("*".equals(acao) && "true".equalsIgnoreCase(acac)) {
                String reqLine = ProbeEngine.requestLine("OPTIONS", url);
                String ev = "Access-Control-Allow-Origin: " + acao + "\n"
                          + "Access-Control-Allow-Credentials: " + acac;

                VulnResult vr = VulnResult.builder()
                        .issueType(IssueType.CORS_MISCONFIG)
                        .severity(Severity.MEDIUM)
                        .url(url)
                        .description("CORS misconfiguration: ACAO='*' with credentials allowed.")
                        .requestLine(reqLine)
                        .evidenceSnippet(ev)
                        .evidence(reqLine + "\n" + ev)
                        .build();
                return Optional.of(vr);
            }
        } catch (Exception ignore) {
            // swallow; return empty if probing fails
        }
        return Optional.empty();
    }

    private static String header(HttpResponse<?> r, String name) {
        return r.headers().firstValue(name).orElse("");
    }
}
