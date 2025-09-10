package com.webkillerai.core.http;

import java.time.Duration;

/** 재시도 조건/지연을 결정하는 정책 */
public interface RetryPolicy {
    /** attempt는 1부터 시작(현재 시도 번호). true면 지연 후 재시도. */
    boolean shouldRetry(int statusCode, int attempt);
    /** attempt에 해당하는 다음 지연 시간. */
    Duration nextDelay(int attempt);
    /** 최대 시도 횟수(마지막 성공 포함). 예: 3이면 최대 3번 시도. */
    int maxAttempts();
}
