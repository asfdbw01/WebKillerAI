package com.webkillerai.core.scanner.budget;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

/** per-run 시간/횟수 예산을 동시에 관리하는 간단 게이트 */
public final class BudgetGate {
    private final AtomicInteger used = new AtomicInteger();
    private final int maxProbes;
    private final long deadlineEpochMs;

    public BudgetGate(int maxProbesPerRun, int maxSecondsPerRun) {
        this.maxProbes = Math.max(1, maxProbesPerRun);
        long seconds = Math.max(1, maxSecondsPerRun);
        this.deadlineEpochMs = Instant.now().toEpochMilli() + seconds * 1000L;
    }

    /** 예산이 남아있으면 1 소모하고 true, 아니면 false */
    public boolean tryConsume() {
        if (System.currentTimeMillis() > deadlineEpochMs) return false;
        int cur = used.incrementAndGet();
        return cur <= maxProbes;
    }

    public int used() { return used.get(); }
    public int remaining() { return Math.max(0, maxProbes - used()); }
    public long deadlineEpochMs() { return deadlineEpochMs; }
}
