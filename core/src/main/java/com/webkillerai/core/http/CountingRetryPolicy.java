package com.webkillerai.core.http;

import java.time.Duration;
import java.util.Objects;

/** RetryPolicy를 감싸 재시도 횟수를 집계하는 얇은 데코레이터. (per-call 사용 권장) */
public final class CountingRetryPolicy implements RetryPolicy {
    private final RetryPolicy delegate;
    private int retries = 0; // shouldRetry(...)가 true를 반환한 횟수

    public CountingRetryPolicy(RetryPolicy delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    /** 주의: 시그니처는 (statusCode, attempt) 순서다. */
    @Override
    public boolean shouldRetry(int statusCode, int attempt) {
        boolean ok = delegate.shouldRetry(statusCode, attempt);
        if (ok) retries++;
        return ok;
    }

    @Override
    public Duration nextDelay(int attempt) {
        return delegate.nextDelay(attempt);
    }

    @Override
    public int maxAttempts() {
        return delegate.maxAttempts();
    }

    /** analyze 한 건에 대해 실제 발생한 재시도 횟수(0 이상). */
    public int getRetryCount() {
        return retries;
    }
}

