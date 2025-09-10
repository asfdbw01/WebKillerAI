package com.webkillerai.core.util;

import java.util.regex.Pattern;

public final class RiskExpression {
    private RiskExpression() {}

    // 허용 패턴: 정수 | 비교 | 범위 (공백 허용), 0~100 범위
    private static final Pattern INT     = Pattern.compile("^\\s*(\\d{1,3})\\s*$");
    private static final Pattern COMPARE = Pattern.compile("^\\s*(>=|<=|>|<)\\s*(\\d{1,3})\\s*$");
    private static final Pattern RANGE   = Pattern.compile("^\\s*(\\d{1,3})\\s*-\\s*(\\d{1,3})\\s*$");

    public static boolean isValid(String expr) {
        if (expr == null || expr.isBlank()) return true; // 빈 값 허용(필터 미적용 의미)
        var m1 = INT.matcher(expr);
        if (m1.matches()) return in01(m1.group(1));
        var m2 = COMPARE.matcher(expr);
        if (m2.matches()) return in01(m2.group(2));
        var m3 = RANGE.matcher(expr);
        if (m3.matches()) {
            int a = Integer.parseInt(m3.group(1));
            int b = Integer.parseInt(m3.group(2));
            return in01(a) && in01(b) && a <= b;
        }
        return false;
    }

    private static boolean in01(String n) {
        try { return in01(Integer.parseInt(n)); } catch (Exception e) { return false; }
    }
    private static boolean in01(int n) { return n >= 0 && n <= 100; }
}
