package com.webkillerai.core.util;

import com.webkillerai.core.model.Severity;

public final class SeverityWeights {
    private SeverityWeights() {}

    /** Severity → Risk Score(0..100) 매핑 */
    public static int toRisk(Severity s) {
        if (s == null) return 0;
        switch (s) {
            case INFO:     return 10;
            case LOW:      return 25;
            case MEDIUM:   return 50;
            case HIGH:     return 75;
            case CRITICAL: return 90;
            default:       return 0;
        }
    }
}
