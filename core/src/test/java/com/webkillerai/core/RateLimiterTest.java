package com.webkillerai.core;

import com.webkillerai.core.util.RateLimiter;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class RateLimiterTest {

    @Disabled("타이밍 의존성으로 CI 불안정할 수 있어 기본 비활성화")
    @Test
    void acquire_shouldThrottle() throws Exception {
        RateLimiter rl = new RateLimiter(1, 5); // 초당 5토큰
        long t0 = System.nanoTime();
        rl.acquire(); // 즉시 통과(초기 토큰 1)
        rl.acquire(); // 대기 발생
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(ms >= 150, "second acquire should wait at least ~150ms (5 tps)");
    }
}
