package com.webkillerai.core.model;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** 런타임 텔레메트리 누적기 (스레드 세이프). */
public final class ScanStats {
    private final AtomicLong requestsTotal = new AtomicLong(0);        // HTTP 시도(재시도 포함) 총합
    private final AtomicLong retriesTotal  = new AtomicLong(0);        // 재시도 횟수 총합
    private final AtomicLong sumWallMsAcrossCalls = new AtomicLong(0); // 각 URL analyzeWithRetry의 벽시계 합
    private final AtomicLong attemptsAcrossCalls  = new AtomicLong(0); // 각 URL별 (1+retries) 합
    private final AtomicInteger maxObservedConcurrency = new AtomicInteger(0);

    /** attempts = (1 + retries) for a URL */
    public void addAttempts(long attempts) {
        attemptsAcrossCalls.addAndGet(attempts);
        requestsTotal.addAndGet(attempts);
    }
    public void addRetries(long retries) {
        retriesTotal.addAndGet(retries);
    }
    public void addWallTimeMs(long wallMs) {
        sumWallMsAcrossCalls.addAndGet(wallMs);
    }
    /** 현재 동시 실행 수를 관측하여 최대값 갱신 */
    public void observeConcurrency(int current) {
        maxObservedConcurrency.accumulateAndGet(current, Math::max);
    }

    public Snapshot snapshot() {
        long req = requestsTotal.get();
        long ret = retriesTotal.get();
        long sumWall = sumWallMsAcrossCalls.get();
        long attempts = Math.max(1, attemptsAcrossCalls.get());
        long avgLatencyMs = sumWall / attempts; // per-attempt 평균(대기 포함, 근사치)
        int maxCC = maxObservedConcurrency.get();
        return new Snapshot(req, ret, maxCC, avgLatencyMs);
    }

    /** 불변 스냅샷 DTO */
    public static final class Snapshot {
        public final long requestsTotal;
        public final long retriesTotal;
        public final int  maxObservedConcurrency;
        public final long avgLatencyMs;
        public Snapshot(long r, long t, int c, long a) {
            this.requestsTotal = r;
            this.retriesTotal = t;
            this.maxObservedConcurrency = c;
            this.avgLatencyMs = a;
        }
    }
}
