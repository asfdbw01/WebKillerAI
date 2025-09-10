package com.webkillerai.core.model;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.Test;

// ✅ 외부 enum Mode 사용
import com.webkillerai.core.model.Mode;

class ScanConfigTest {

    @Test
    void defaultsAreValid() {
        ScanConfig cfg = new ScanConfig().setTarget("https://example.com");
        cfg.validate();

        assertThat(cfg.getTarget()).isEqualTo("https://example.com");
        assertThat(cfg.getMaxDepth()).isEqualTo(2);
        assertThat(cfg.isSameDomainOnly()).isTrue();
        // 🔁 여기만 변경: ScanConfig.Mode → Mode
        assertThat(cfg.getMode()).isEqualTo(Mode.SAFE);
        assertThat(cfg.getTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(cfg.getTimeoutMs()).isEqualTo(10_000L);
        assertThat(cfg.getConcurrency()).isEqualTo(4);
        assertThat(cfg.isFollowRedirects()).isTrue();
        assertThat(cfg.getOutputDir()).isEqualTo(Path.of("out"));
        // OutputFormat은 내부 enum 유지
        assertThat(cfg.getOutputFormat()).isEqualTo(ScanConfig.OutputFormat.JSON);
        assertThat(cfg.getRps()).isEqualTo(10);
    }

    @Test
    void setTimeoutMsClampsToPositive() {
        ScanConfig cfg = new ScanConfig().setTarget("https://example.com");

        cfg.setTimeoutMs(0);
        assertThat(cfg.getTimeoutMs()).isEqualTo(1L);

        cfg.setTimeoutMs(-5);
        assertThat(cfg.getTimeoutMs()).isEqualTo(1L);

        cfg.validate(); // 여전히 유효해야 함
    }

    @Test
    void setConcurrencyHasLowerBoundOne() {
        ScanConfig cfg = new ScanConfig()
                .setTarget("https://example.com")
                .setConcurrency(0); // 하한 적용

        assertThat(cfg.getConcurrency()).isEqualTo(1);
        cfg.validate();
    }

    @Test
    void validateRequiresTarget() {
        ScanConfig cfg = new ScanConfig(); // target 미설정
        assertThrows(NullPointerException.class, cfg::validate);
    }

    @Test
    void validateRejectsNegativeDepth() {
        ScanConfig cfg = new ScanConfig()
                .setTarget("https://example.com")
                .setMaxDepth(-1);

        assertThatThrownBy(cfg::validate)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxDepth must be >= 0");
    }

    @Test
    void validateRejectsNonPositiveRps() {
        ScanConfig cfg = new ScanConfig()
                .setTarget("https://example.com");
        cfg.setRps(0);

        assertThatThrownBy(cfg::validate)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rps must be > 0");
    }

    @Test
    void validateRejectsNullOutputDirOrFormat() {
        ScanConfig cfg = new ScanConfig().setTarget("https://example.com");

        // outputDir null
        cfg.setOutputDir(null);
        assertThatThrownBy(cfg::validate)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("outputDir");

        // 복구 후 format null
        cfg.setOutputDir(Path.of("out"));
        cfg.setOutputFormat(null);
        assertThatThrownBy(cfg::validate)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("outputFormat");
    }
}
