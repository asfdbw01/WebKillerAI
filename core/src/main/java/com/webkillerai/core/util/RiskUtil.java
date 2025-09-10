package com.webkillerai.core.util;

import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;

import java.util.*;
import java.util.stream.Collectors;

public final class RiskUtil {
    private RiskUtil() {}

    // severity → risk 맵(HTML 대체표와 동일: 10/25/50/75/90)
    public static int severityToRisk(Severity s) {
        if (s == null) return 10;
        return switch (s) {
            case INFO -> 10;
            case LOW -> 25;
            case MEDIUM -> 50;
            case HIGH -> 75;
            case CRITICAL -> 90;
        };
    }

    public static RiskSummary summarize(Collection<VulnResult> issues) {
        if (issues == null || issues.isEmpty()) return new RiskSummary(0, 0, 0, 0);
        List<Integer> scores = new ArrayList<>(issues.size());
        for (VulnResult v : issues) {
            Integer rs = (v == null) ? null : v.getRiskScore();
            if (rs == null) rs = severityToRisk(v != null ? v.getSeverity() : null);
            scores.add(clamp(rs, 0, 100));
        }
        return summarizeScores(scores);
    }

    // 점수 직접 집계(테스트 등에서 사용)
    public static RiskSummary summarizeScores(Collection<Integer> input) {
        if (input == null || input.isEmpty()) return new RiskSummary(0, 0, 0, 0);
        List<Integer> s = input.stream()
                .filter(Objects::nonNull)
                .map(x -> clamp(x, 0, 100))
                .sorted()
                .collect(Collectors.toList());

        int n = s.size();
        int max = s.get(n - 1);
        long sum = 0; for (int x : s) sum += x;
        int avg = (int) Math.round(sum / (double) n);

        int idx = (int) Math.floor(0.95 * (n - 1)); // 0-based lower nearest-rank (n-1 스케일)
        if (idx < 0) idx = 0; if (idx >= n) idx = n - 1;
        int p95 = s.get(idx);

        return new RiskSummary(avg, p95, max, n);
    }

    private static int clamp(int v, int lo, int hi) {
        return Math.min(hi, Math.max(lo, v));
    }

    public record RiskSummary(int avg, int p95, int max, int count) {}
}
