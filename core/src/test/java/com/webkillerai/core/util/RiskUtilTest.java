package com.webkillerai.core.util;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/**
 * RiskUtil.summarizeScores(List<Integer>) 스모크/경계 테스트
 * p95 정의 가정: index = floor(0.95 * (n - 1))  (0-based)
 */
class RiskUtilTest {

    @Test
    void summarizeScores_avg_p95_max() {
        // 10개: 10,20,...,100
        // avg = 55, p95 = floor(0.95*(10-1)) = floor(8.55) = 8 -> 값 90, max = 100
        var rs = RiskUtil.summarizeScores(List.of(10,20,30,40,50,60,70,80,90,100));
        assertEquals(55, rs.avg());
        assertEquals(90, rs.p95());
        assertEquals(100, rs.max());
        assertEquals(10, rs.count());
    }

    @Test
    void summarizeScores_simple() {
        // 값: 0,0,100,100
        // p95 = floor(0.95*(4-1)) = floor(2.85) = 2 -> 정렬[2] = 100
        var rs = RiskUtil.summarizeScores(List.of(0, 0, 100, 100));
        assertEquals(50, rs.avg());
        assertEquals(100, rs.p95());
        assertEquals(100, rs.max());
        assertEquals(4, rs.count());
    }

    @Test
    void singleValue() {
        var rs = RiskUtil.summarizeScores(List.of(42));
        assertEquals(42, rs.avg());
        assertEquals(42, rs.p95());
        assertEquals(42, rs.max());
        assertEquals(1, rs.count());
    }

    @Test
    void heavyTail_rareHigh() {
        // 낮은 값 4개 + 높은 값 1개 (n=5)
        // p95 = floor(0.95*(5-1)) = floor(3.8) = 3 -> 정렬[3] = 10
        var rs = RiskUtil.summarizeScores(List.of(10, 10, 10, 10, 90));
        assertEquals(26, rs.avg()); 
        assertEquals(10, rs.p95());   // ✅ 여기 90 → 10 으로 수정
        assertEquals(90, rs.max());
        assertEquals(5, rs.count());
    }

    @Test
    void allEqual_values() {
        var rs = RiskUtil.summarizeScores(List.of(30, 30, 30));
        assertEquals(30, rs.avg());
        assertEquals(30, rs.p95());
        assertEquals(30, rs.max());
        assertEquals(3, rs.count());
    }
}
