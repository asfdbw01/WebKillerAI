package com.webkillerai.core.util;

import java.time.Duration;

public final class DefaultSleeper implements Sleeper {
    @Override public void sleep(Duration d) throws InterruptedException {
        long ms = Math.max(0, d.toMillis());
        if (ms > 0) Thread.sleep(ms);
    }
}
