package com.webkillerai.core.crawler.robots;

final class FrozenClock implements RobotsClock {
    private long now;
    FrozenClock(long start) { this.now = start; }
    void plusMillis(long d) { now += d; }
    @Override public long nowMillis() { return now; }
}
