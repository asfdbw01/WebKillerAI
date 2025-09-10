package com.webkillerai.core.util;

import java.time.Duration;

public interface Sleeper {
    void sleep(Duration d) throws InterruptedException;
}
