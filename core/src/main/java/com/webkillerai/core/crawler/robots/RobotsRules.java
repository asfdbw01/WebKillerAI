package com.webkillerai.core.crawler.robots;

import java.util.ArrayList;
import java.util.List;

public final class RobotsRules {
    public final List<String> allow = new ArrayList<>();
    public final List<String> disallow = new ArrayList<>();

    public RobotsRules addAllow(String path) {
        if (path != null && !path.isBlank()) allow.add(path.trim());
        return this;
    }

    public RobotsRules addDisallow(String path) {
        // Disallow: (빈값) 은 규칙으로 취급하지 않음
        if (path != null && !path.isBlank()) disallow.add(path.trim());
        return this;
    }

    /** 엔진 규칙으로 컴파일해서 UaGroup으로 변환 */
    public RobotsEngine.UaGroup toEngineGroup(String name) {
        List<RobotsEngine.Rule> compiled = new ArrayList<>();
        for (String v : allow) {
            var r = RobotsEngine.compileRule(RobotsEngine.RuleType.ALLOW, v);
            if (r != null) compiled.add(r);
        }
        for (String v : disallow) {
            var r = RobotsEngine.compileRule(RobotsEngine.RuleType.DISALLOW, v);
            if (r != null) compiled.add(r);
        }
        return new RobotsEngine.UaGroup(name, compiled);
    }
}
