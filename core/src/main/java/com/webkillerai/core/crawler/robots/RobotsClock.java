package com.webkillerai.core.crawler.robots;

public interface RobotsClock {
    long nowMillis();
    RobotsClock SYSTEM = System::currentTimeMillis;
}
