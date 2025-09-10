// core/src/main/java/com/webkillerai/core/scanner/ActiveDetectorOrchestrator.java
package com.webkillerai.core.scanner;

import com.webkillerai.core.config.FeatureMatrix;
import com.webkillerai.core.model.Mode;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.scanner.budget.BudgetGate;
import com.webkillerai.core.scanner.dedupe.DedupeKey;
import com.webkillerai.core.scanner.probe.ProbeEngine;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 액티브 디텍터 실행 오케스트레이터(collect-all):
 *  - 1) paramless pass  : paramKey=null로 모든 디텍터 호출(OR/CORS/Mixed 등은 여기서 동작)
 *  - 2) param pass      : 샘플링된 파라미터 키들에 대해 디텍터 호출(XSS/SQLi/LFI/SSTI 등)
 *  - 예산(BudgetGate)과 중복 억제(DedupeKey) 적용, 전체 결과 누적 반환
 */
public final class ActiveDetectorOrchestrator {

    /** 액티브 디텍터 최소 계약. (url, paramKey) 단위로 1회 시도 권장 */
    @FunctionalInterface
    public interface Detector {
        /** paramKey==null이면 URL 단위 디텍터로, 아니면 해당 파라미터 대상 */
        Optional<VulnResult> detect(ProbeEngine engine, ScanConfig cfg, URI url, String paramKey);
    }

    private final ProbeEngine engine;
    private final Map<DedupeKey, Boolean> dedupe = new ConcurrentHashMap<>();

    public ActiveDetectorOrchestrator(ProbeEngine engine) {
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    /**
     * 액티브 디텍터 실행(collect-all).
     */
    public List<VulnResult> runActive(ScanConfig cfg,
                                      URI url,
                                      List<String> candidateParams,
                                      List<Detector> detectors) {
        Objects.requireNonNull(cfg, "cfg");
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(detectors, "detectors");

        Mode mode = cfg.getMode();
        if (!FeatureMatrix.isAnyActive(mode)) {
            return Collections.emptyList(); // SAFE 등 액티브 OFF
        }

        // 파라미터 샘플링(힌트 우선 + cap 적용)
        List<String> sampledParams = sampleParams(cfg, candidateParams);

        // 예산 게이트 (모드별 기본치)
        BudgetGate gate = budgetFor(cfg, mode,
                Integer.getInteger("wk.safePlus.maxProbesPerRun", 300),
                Integer.getInteger("wk.safePlus.maxSecondsPerRun", 30));

        final LinkedHashMap<DedupeKey, VulnResult> acc = new LinkedHashMap<>();

        // ===== 1) PARAMLESS PASS =====
        for (Detector d : detectors) {
            if (!gate.tryConsume()) break;
            try {
                d.detect(engine, cfg, url, null).ifPresent(v -> putIfAbsent(acc, v, null));
            } catch (RuntimeException ignore) { /* 디텍터 단위 오류 무시 */ }
        }

        // ===== 2) PARAM PASS =====
        for (String pk : sampledParams) {
            for (Detector d : detectors) {
                if (!gate.tryConsume()) break; // 예산 소진 시 중단
                try {
                    d.detect(engine, cfg, url, pk).ifPresent(v -> putIfAbsent(acc, v, pk));
                } catch (RuntimeException ignore) { /* 다음으로 */ }
            }
        }

        return new ArrayList<>(acc.values());
    }

    // ---------------- internal helpers ----------------

    /** 결과 누적(중복 억제). dedupe 키: (url, paramKey or "-", issueType, signal=null) */
    private void putIfAbsent(LinkedHashMap<DedupeKey, VulnResult> acc, VulnResult v, String paramKey) {
        URI u = toUri(v.getUrl());
        String pk = (paramKey == null || paramKey.isBlank()) ? "-" : paramKey;
        String issue = (v.getIssueType() == null ? "-" : v.getIssueType().name());

        DedupeKey key = DedupeKey.of(u, pk, issue, null);
        if (dedupe.putIfAbsent(key, Boolean.TRUE) == null) {
            acc.put(key, v);
        }
    }

    /** 파라미터 샘플링: 힌트 우선 + 모드별 cap */
    private static List<String> sampleParams(ScanConfig cfg, List<String> params) {
        Mode m = cfg.getMode();
        int cap = (m == Mode.AGGRESSIVE_LITE)
                ? cfg.aggressive().getMaxParamsPerUrl()
                : Math.max(1, cfg.getMaxParamsPerUrl() > 0
                        ? cfg.getMaxParamsPerUrl()
                        : FeatureMatrix.maxParamsPerUrlDefault(m));

        LinkedHashSet<String> ordered = new LinkedHashSet<>();

        // 힌트 우선 고정(있으면)
        if (cfg.getSqliParamHints() != null && !cfg.getSqliParamHints().isEmpty()) {
            ordered.add(cfg.getSqliParamHints().get(0));
        }
        if (cfg.getXssParamHints() != null && !cfg.getXssParamHints().isEmpty()) {
            ordered.add(cfg.getXssParamHints().get(0));
        }

        if (params != null) {
            for (String p : params) {
                if (p != null && !p.isBlank()) ordered.add(p);
            }
        }

        List<String> res = new ArrayList<>(ordered);
        if (res.size() > cap) {
            ArrayList<String> trimmed = new ArrayList<>(Math.min(cap, res.size()));
            for (int i = 0; i < Math.min(2, res.size()); i++) trimmed.add(res.get(i));
            Random rnd = new Random();
            while (trimmed.size() < cap) {
                String pick = res.get(rnd.nextInt(res.size()));
                if (!trimmed.contains(pick)) trimmed.add(pick);
            }
            return trimmed;
        }
        return res;
    }

    private static BudgetGate budgetFor(ScanConfig cfg, Mode m, int safePlusDefaultProbes, int safePlusDefaultSec) {
        if (m == Mode.AGGRESSIVE_LITE) {
            int maxProbes  = Integer.getInteger("wk.aggr.maxProbesPerRun", 800);
            int maxSeconds = Math.max(1, cfg.aggressive().getRunTimeBudgetMs() / 1000);
            return new BudgetGate(maxProbes, maxSeconds);
        }
        if (m == Mode.SAFE_PLUS) {
            int maxProbes  = Integer.getInteger("wk.safePlus.maxProbesPerRun", safePlusDefaultProbes);
            int maxSeconds = Integer.getInteger("wk.safePlus.maxSecondsPerRun", safePlusDefaultSec);
            return new BudgetGate(maxProbes, maxSeconds);
        }
        // SAFE — 액티브 미사용 (방어적으로 작은 예산)
        return new BudgetGate(1, 1);
    }

    /** v.getUrl() 이 URI든 String이든 안전하게 URI로 변환 */
    private static URI toUri(Object val) {
        if (val instanceof URI) return (URI) val;
        if (val == null) return URI.create("about:blank");
        return URI.create(val.toString());
    }
}
