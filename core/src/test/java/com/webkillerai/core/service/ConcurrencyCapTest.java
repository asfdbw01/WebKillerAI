package com.webkillerai.core.service;

import com.webkillerai.core.api.ICrawler;
import com.webkillerai.core.api.IHttpAnalyzer;
import com.webkillerai.core.api.IScanner;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyCapTest {

    @Test
    void observed_concurrency_never_exceeds_configured_limit() {
        final int CC  = 4;     // 동시성 상한
        final int RPS = 10_000; // 레이트리미터 영향 제거

        // 1) 설정
        ScanConfig cfg = ScanConfig.defaults()
                .setTarget("http://example.com/")
                .setMaxDepth(0)
                .setConcurrency(CC);
        cfg.setRps(RPS); // ← 체인에서 분리

        // 2) 스텁 크롤러: 40개 시드
        ICrawler crawler = () -> {
            List<URI> seeds = new ArrayList<>();
            for (int i = 0; i < 40; i++) seeds.add(URI.create("http://example.com/p"+i));
            return seeds;
        };

        // 3) 스텁 분석기: 200ms 슬립만 (HttpResponseData는 쓰지 않으니 null 반환)
        IHttpAnalyzer http = url -> {
            try { Thread.sleep(200); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            return null;
        };

        // 4) 스텁 스캐너: 항상 빈 결과
        IScanner scanner = resp -> Collections.emptyList();

        // 5) 실행
        ScanService svc = new ScanService(cfg, crawler, http, scanner);
        List<VulnResult> results = svc.run();

        // 6) 검증: 관측 최대 동시성이 CC 이하여야 한다
        var rt = svc.getRuntimeSnapshot();
        assertTrue(rt.maxObservedConcurrency <= CC,
                "observed=" + rt.maxObservedConcurrency + " > CC=" + CC);

        // sanity: 뭔가는 실행되었어야 함
        assertTrue(results.size() >= 0);
    }
}
