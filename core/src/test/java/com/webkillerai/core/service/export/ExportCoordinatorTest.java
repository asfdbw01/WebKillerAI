package com.webkillerai.core.service.export;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ExportCoordinator — order & return path (no existence check for empty results)")
class ExportCoordinatorTest {

    @TempDir
    Path tmp;

    private static ScanConfig cfg(String target) {
        ScanConfig c = new ScanConfig();
        c.setTarget(target);
        c.setMaxDepth(1);
        return c;
    }

    @Test
    @DisplayName("formats=[html] ⇒ 반환 경로는 .html")
    void export_html_only() throws Exception {
        var coord = new ExportCoordinator();
        List<VulnResult> results = List.<VulnResult>of(); // 빈 결과(정책상 파일 생성 생략 가능)

        Path last = coord.exportAll(
                tmp,
                cfg("https://ex.com"),
                results,
                "2025-03-01T21:34:00Z",
                Set.of("html")
        );

        assertThat(last).isNotNull();
        assertThat(last.getFileName().toString()).endsWith(".html");
    }

    @Test
    @DisplayName("formats=[json,html] ⇒ 반환 경로는 .html (마지막 우선)")
    void export_html_and_json_return_html() throws Exception {
        var coord = new ExportCoordinator();
        List<VulnResult> results = List.<VulnResult>of();

        Path last = coord.exportAll(
                tmp,
                cfg("https://ex.com"),
                results,
                "2025-03-01T21:34:00Z",
                new LinkedHashSet<>(Arrays.asList("json", "html"))
        );

        assertThat(last).isNotNull();
        assertThat(last.getFileName().toString()).endsWith(".html");
        // JSON 물리 파일 존재 여부는 정책상 보장되지 않으므로 검증하지 않음
    }
}
