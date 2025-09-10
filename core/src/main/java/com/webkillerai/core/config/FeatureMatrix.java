// core/src/main/java/com/webkillerai/core/config/FeatureMatrix.java
package com.webkillerai.core.config;

import com.webkillerai.core.model.Mode;

/**
 * 모드(플랜)별 기능 스위치 중앙 테이블.
 * - 여기만 수정하면 전체 동작 스위치가 바뀜
 * - 디텍터/오케스트레이터는 cfg.getMode() 직접 비교 대신 여기 메서드만 호출
 *
 * 합의 스펙:
 *   AGGRESSIVE = SAFE_PLUS ∪ AGGRESSIVE_LITE  (비파괴: GET/HEAD/OPTIONS)
 *   SAFE_PLUS : XSS_REFLECTED, SQLI_ERROR, CORS_MISCONFIG, OPEN_REDIRECT
 *   AGG_LITE  : PATH_TRAVERSAL(LFI), SSTI_PATTERN, OPEN_REDIRECT, MIXED_CONTENT
 */
public final class FeatureMatrix {
    private FeatureMatrix() {}

    // ===== Active(능동) 프로브 온/오프 =====

    /** Reflected XSS (무해 토큰 주입) */
    public static boolean activeXssReflected(Mode m) {
        // SAFE_PLUS + AGGRESSIVE (AGG_LITE는 OFF)
        return m == Mode.SAFE_PLUS || m == Mode.AGGRESSIVE;
    }

    /** SQLi (에러 기반 최소 페이로드) */
    public static boolean activeSqli(Mode m) {
        // SAFE_PLUS + AGGRESSIVE (AGG_LITE는 OFF)
        return m == Mode.SAFE_PLUS || m == Mode.AGGRESSIVE;
    }

    /** CORS 오구성 (Origin 헤더/프리플라이트) */
    public static boolean activeCors(Mode m) {
        // 읽기 전용이라 AGGRESSIVE에서도 켬. (AGG_LITE는 OFF)
        return m == Mode.SAFE_PLUS || m == Mode.AGGRESSIVE;
    }

    /** Open Redirect (외부 Location) */
    public static boolean activeOpenRedirect(Mode m) {
        // 세 모드에서 모두 ON (SAFE 제외)
        return m == Mode.SAFE_PLUS || m == Mode.AGGRESSIVE_LITE || m == Mode.AGGRESSIVE;
    }

    /** Path Traversal / LFI (소량 사전) */
    public static boolean activePathTraversal(Mode m) {
        // AGG_LITE + AGGRESSIVE
        return m == Mode.AGGRESSIVE_LITE || m == Mode.AGGRESSIVE;
    }

    /** SSTI (라이트) */
    public static boolean activeSsti(Mode m) {
        // AGG_LITE + AGGRESSIVE
        return m == Mode.AGGRESSIVE_LITE || m == Mode.AGGRESSIVE;
    }

    /** Mixed Content (HTTPS 문서 내 http:// 리소스) */
    public static boolean activeMixedContent(Mode m) {
        // AGG_LITE + AGGRESSIVE (SAFE_PLUS는 OFF)
        return m == Mode.AGGRESSIVE_LITE || m == Mode.AGGRESSIVE;
    }

    // ===== Anomaly(경량 탐지) 온/오프 =====
    public static boolean anomalyContentTypeMismatch(Mode m) {
        return true; // 전 모드 ON
    }

    public static boolean anomalyStacktraceToken(Mode m) {
        return true; // 전 모드 ON
    }

    public static boolean anomalySizeDelta(Mode m) {
        return false; // 기본 OFF (원하면 true로)
    }

    // ===== 모드별 기본 상한/튜닝값 =====

    /** 한 번에 액티브 대상으로 삼을 엔드포인트 상한 (오케스트레이터에서 사용) */
    public static int endpointCap(Mode m) {
        if (m == Mode.SAFE_PLUS)       return 8;
        if (m == Mode.AGGRESSIVE_LITE) return 10;
        if (m == Mode.AGGRESSIVE)      return 16;
        return 0; // SAFE: 액티브 없음
    }

    /** URL당 변조 파라미터 기본 상한 (ScanConfig가 별도 지정하면 그 값을 우선) */
    public static int maxParamsPerUrlDefault(Mode m) {
        if (m == Mode.SAFE)            return 0;
        if (m == Mode.SAFE_PLUS)       return 3;
        if (m == Mode.AGGRESSIVE_LITE) return 4;
        if (m == Mode.AGGRESSIVE)      return 6; // 넉넉히
        return 0;
    }

    /**
     * 액티브 프로브 기본 RPS (패시브 RPS와 독립)
     * - SAFE_PLUS : max(2, min(3, passiveRps))
     * - AGG_LITE  : max(3, min(5, passiveRps))
     * - AGGRESSIVE: max(4, min(7, passiveRps))
     */
    public static int activeDefaultRps(Mode m, int passiveRps) {
        if (m == Mode.SAFE_PLUS)       return Math.max(2, Math.min(3, passiveRps));
        if (m == Mode.AGGRESSIVE_LITE) return Math.max(3, Math.min(5, passiveRps));
        if (m == Mode.AGGRESSIVE)      return Math.max(4, Math.min(7, passiveRps));
        return 0; // SAFE: 미사용
    }

    /** 현재 모드에서 액티브 프로브를 “어떤 것이라도” 켤지 여부 (오케스트레이터 생성 게이트) */
    public static boolean isAnyActive(Mode m) {
        return activeXssReflected(m) || activeSqli(m) || activeCors(m)
            || activeOpenRedirect(m) || activePathTraversal(m)
            || activeSsti(m) || activeMixedContent(m);
    }
}
