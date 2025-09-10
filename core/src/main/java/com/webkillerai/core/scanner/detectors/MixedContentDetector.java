// core/src/main/java/com/webkillerai/core/scanner/detectors/MixedContentDetector.java
package com.webkillerai.core.scanner.detectors;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.ActiveDetectorOrchestrator;
import com.webkillerai.core.scanner.probe.ProbeEngine;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Mixed Content detector
 * - HTTPS 문서에서 http:// 서브리소스 참조를 찾는다.
 * - 모드 게이팅은 Orchestrator/FeatureMatrix가 담당.
 * - 기존 호출부(3-인자)와 오케스트레이터(4-인자)를 모두 지원한다.
 */
public final class MixedContentDetector implements ActiveDetectorOrchestrator.Detector {

    /** 오케스트레이터용 시그니처(호환): paramKey는 사용하지 않음 */
    @Override
    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI url, String paramKey) {
        return detect(engine, cfg, url);
    }

    /** 기존 호출부 호환 시그니처 */
    public Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI url) {
        if (!"https".equalsIgnoreCase(url.getScheme())) return Optional.empty();

        try {
            // 현재 엔진 시그니처: get(URI, Map<String,String>) → HttpResponse<String>
            HttpResponse<String> rsp = engine.get(
                url,
                java.util.Map.of("Accept", "text/html,application/xhtml+xml")
            );
            String html = rsp.body();
            if (html == null || html.isEmpty()) return Optional.empty();

            List<String> mixed = findMixedUrls(html, url);
            if (mixed.isEmpty()) return Optional.empty();

            String reqLine  = engine.requestLine("GET", url);
            String joined   = String.join("\n", mixed.subList(0, Math.min(5, mixed.size())));
            String snippet  = clamp(joined, 512); // evidenceSnippet ≤512 정책

            return Optional.of(
                VulnResult.builder()
                    .issueType(IssueType.MIXED_CONTENT)
                    .severity(Severity.LOW) // 프로젝트 맵핑: Mixed = LOW
                    .url(url)               // Builder는 URI를 받음
                    .requestLine(reqLine)
                    .evidenceSnippet(snippet)
                    .build()
            );
        } catch (Exception ignore) {
            // 디텍터 예외는 전체 중단 사유가 아님
        }
        return Optional.empty();
    }

    /** HTML에서 http:// 서브리소스 참조를 추출 */
    static List<String> findMixedUrls(String html, URI base) {
        List<String> hits = new ArrayList<>();
        try {
            Document d = Jsoup.parse(html, base.toString());
            collect(d, hits, "script[src]");
            collect(d, hits, "img[src]");
            collect(d, hits, "link[href]");        // stylesheet, prefetch 등
            collect(d, hits, "iframe[src]");
            collect(d, hits, "audio[src], video[src], source[src]");
            // TODO: srcset/object[data]/form[action]/inline CSS url(...) 확대 가능
        } catch (Exception ignore) {}
        return hits;
    }

    private static void collect(Document d, List<String> out, String css) {
        for (Element e : d.select(css)) {
            String v = e.hasAttr("src") ? e.attr("abs:src") : e.attr("abs:href");
            if (v != null && v.toLowerCase(Locale.ROOT).startsWith("http://")) {
                String tag  = e.tagName();
                String attr = e.hasAttr("src") ? "src" : "href";
                out.add("<" + tag + " " + attr + "=\"" + v + "\">"); // 간단 증거 라인
                if (out.size() >= 20) return; // 과도 수집 방지
            }
        }
    }

    private static String clamp(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max);
    }
}
