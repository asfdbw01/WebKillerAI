package com.webkillerai.core.http;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class RetryPolicyTest {

    @Test
    void shouldRetry_onlyOn_429_5xx_or_minus1_and_respect_maxAttempts_3() {
        var p = new DefaultRetryPolicy();

        assertEquals(3, p.maxAttempts(), "maxAttempts must be 3");

        int[] retryables = {429, 500, 502, 503, 599, -1};
        for (int sc : retryables) {
            assertTrue(p.shouldRetry(sc, 1), "should retry on first failure for " + sc);
            assertTrue(p.shouldRetry(sc, 2), "should retry on second failure for " + sc);
            assertFalse(p.shouldRetry(sc, 3), "must stop retrying at attempt=3 for " + sc);
        }

        int[] nonRetry = {200, 204, 301, 302, 304, 400, 401, 403, 404, 418};
        for (int sc : nonRetry) {
            assertFalse(p.shouldRetry(sc, 1), "must not retry for non-retryable code " + sc);
        }
    }

    @Test
    void backoff_is_exponential_with_jitter_plus_minus_10_percent() {
        var p = new DefaultRetryPolicy();

        // Spec: 250 → 500 → 1000 (ms), each with ±10% jitter
        Duration d1 = p.nextDelay(1); // before 2nd attempt
        Duration d2 = p.nextDelay(2); // before 3rd attempt
        Duration d3 = p.nextDelay(3); // (no further attempt expected, but value should follow pattern)

        assertBetween(d1.toMillis(), 225, 275, "attempt=1 backoff");
        assertBetween(d2.toMillis(), 450, 550, "attempt=2 backoff");
        assertBetween(d3.toMillis(), 900, 1100, "attempt=3 backoff");
    }

    // ---- helpers ----
    private static void assertBetween(long actual, long min, long max, String label) {
        assertTrue(actual >= min && actual <= max,
                () -> label + " out of range: " + actual + "ms (expected " + min + "~" + max + "ms)");
    }
}
