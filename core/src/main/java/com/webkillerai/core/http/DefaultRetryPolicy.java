package com.webkillerai.core.http;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;

/** 429/5xx에서만 재시도. 250ms → 500ms → 1000ms (±10% Jitter) */
public final class DefaultRetryPolicy implements RetryPolicy {
    private final int maxAttempts;
    private final long baseMillis;

    public DefaultRetryPolicy() { this(3, 250); }
    public DefaultRetryPolicy(int maxAttempts, long baseMillis) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.baseMillis = Math.max(1, baseMillis);
    }

    @Override public boolean shouldRetry(int statusCode, int attempt) {
        if (attempt >= maxAttempts) return false;
        return statusCode == 429 || statusCode >= 500 || statusCode == -1;
    }

    @Override public Duration nextDelay(int attempt) {
        long pow = 1L << (attempt - 1);          // 1,2,4...
        long raw = baseMillis * pow;             // 250, 500, 1000...
        double jitter = 0.9 + ThreadLocalRandom.current().nextDouble(0.2); // ±10%
        return Duration.ofMillis((long)(raw * jitter));
    }

    @Override public int maxAttempts() { return maxAttempts; }
}
