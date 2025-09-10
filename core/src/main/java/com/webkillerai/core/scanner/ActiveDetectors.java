// core/src/main/java/com/webkillerai/core/scanner/ActiveDetectors.java
package com.webkillerai.core.scanner;

import com.webkillerai.core.config.FeatureMatrix;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.scanner.ActiveDetectorOrchestrator.Detector;
import com.webkillerai.core.scanner.detectors.MixedContentDetector;
import com.webkillerai.core.scanner.detectors.OpenRedirectDetector;
import com.webkillerai.core.scanner.detectors.PathTraversalDetector;
import com.webkillerai.core.scanner.detectors.SstiSimpleDetector;
import com.webkillerai.core.scanner.detectors.CorsMisconfigDetector;
import com.webkillerai.core.scanner.detectors.XssReflectedDetector;
import com.webkillerai.core.scanner.detectors.SqliErrorDetector; // ← 추가

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 모드/설정에 따른 액티브 디텍터 목록을 구성한다.
 * Mixed Content + Open Redirect + Path Traversal(LFI) + SSTI(Simple) + CORS + XSS(Reflected) + SQLi(Error)
 */
public final class ActiveDetectors {
    private ActiveDetectors() {}

    public static List<Detector> build(ScanConfig cfg) {
        Mode m = cfg.getMode();
        List<Detector> detectors = new ArrayList<>();

        // Mixed Content (HTTPS 문서 내 http:// 서브리소스)
        if (FeatureMatrix.activeMixedContent(m)) {
            detectors.add(new MixedContentDetector());
        }

        // Open Redirect — URL당 1회
        if (FeatureMatrix.activeOpenRedirect(m)) {
            detectors.add((engine, cfg2, url2, paramKey) -> {
                if (paramKey != null) return Optional.empty();
                return new OpenRedirectDetector().detect(engine, cfg2, url2);
            });
        }

        // Path Traversal / LFI — paramKey별
        if (FeatureMatrix.activePathTraversal(m)) {
            detectors.add((engine, cfg2, url2, paramKey) ->
                new PathTraversalDetector().detect(engine, cfg2, url2, paramKey)
            );
        }

        // SSTI (Simple) — paramKey 지정 시 해당 키, 없으면 자동 힌트
        if (FeatureMatrix.activeSsti(m)) {
            detectors.add((engine, cfg2, url2, paramKey) -> {
                var d = new SstiSimpleDetector();
                return (paramKey != null && !paramKey.isBlank())
                        ? d.detect(engine, cfg2, url2, paramKey)
                        : d.detect(engine, cfg2, url2);
            });
        }

        // CORS Misconfiguration — URL당 1회
        if (FeatureMatrix.activeCors(m)) {
            detectors.add((engine, cfg2, url2, paramKey) -> {
                if (paramKey != null) return Optional.empty();
                return new CorsMisconfigDetector().detect(engine, cfg2, url2);
            });
        }

        // XSS (Reflected) — paramKey 기반
        if (FeatureMatrix.activeXssReflected(m)) {
            detectors.add((engine, cfg2, url2, paramKey) ->
                new XssReflectedDetector().detect(engine, cfg2, url2, paramKey)
            );
        }

        // SQLi (Error-based) — paramKey 기반
        if (FeatureMatrix.activeSqli(m)) {
            detectors.add((engine, cfg2, url2, paramKey) ->
                new SqliErrorDetector().detect(engine, cfg2, url2, paramKey)
            );
        }

        return detectors;
    }
}
