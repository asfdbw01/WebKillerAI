package com.webkillerai.core;

import com.webkillerai.core.model.ScanConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ScanConfigTest {

    @Test
    void validate_withMinimalValidConfig_shouldPass() {
        ScanConfig cfg = new ScanConfig();
        cfg.setTarget("https://example.com");
        cfg.setMaxDepth(1); // 기타 필드는 기본값(OK)
        assertDoesNotThrow(cfg::validate);
    }

    @Test
    void validate_pass_whenRpsPositive() {
        ScanConfig cfg = new ScanConfig();
        cfg.setTarget("https://example.com");
        cfg.setRps(10); // > 0 이면 통과
        assertDoesNotThrow(cfg::validate);
    }

    @Test
    void validate_fail_whenRpsZeroOrNegative() {
        ScanConfig cfg = new ScanConfig();
        cfg.setTarget("https://example.com"); // target null로 인한 NPE 방지
        cfg.setRps(0); // 실패 케이스
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, cfg::validate);
        assertTrue(ex.getMessage().toLowerCase().contains("rps"));
    }
}
