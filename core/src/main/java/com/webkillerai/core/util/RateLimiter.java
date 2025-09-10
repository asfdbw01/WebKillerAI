package com.webkillerai.core.util;

public final class RateLimiter {
    private final long capacity;
    private final long refillPerSecond;
    private double tokens;
    private long lastNs;

    public RateLimiter(long capacity, long refillPerSecond) {
        this.capacity = capacity;
        this.refillPerSecond = refillPerSecond;
        this.tokens = capacity;
        this.lastNs = System.nanoTime();
    }

    public synchronized void acquire() throws InterruptedException {
        for (;;) {
            refill();
            if (tokens >= 1.0) { tokens -= 1.0; return; }
            this.wait(5);
        }
    }

    private void refill() {
        long now = System.nanoTime();
        double add = (now - lastNs) / 1_000_000_000.0 * refillPerSecond;
        if (add > 0) {
            tokens = Math.min(capacity, tokens + add);
            lastNs = now;
        }
    }
}
