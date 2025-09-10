package com.webkillerai.core;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.service.export.JsonReportExporter;
import com.webkillerai.core.service.export.ReportExporter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class JsonReportExporterTest {

    @TempDir
    Path tmp;

    @Test
    void export_shouldCreateReportFile_withBasicKeys_andRpsInMetaAndSummary() throws Exception {
        // given
        ScanConfig cfg = new ScanConfig();
        cfg.setTarget("https://example.com");
        cfg.setMaxDepth(1);
        cfg.setRps(7); // ← 이번 라운드 핵심: RPS 반영 확인
        ReportExporter exporter = new JsonReportExporter();
        List<VulnResult> results = List.of(); // 빈 결과여도 Report 생성

        // when
        Path out = exporter.export(tmp, cfg, results, Instant.now().toString());

        // then
        assertTrue(Files.exists(out), "Report file should exist");
        String json = Files.readString(out);

        // 기본 섹션 존재
        assertTrue(json.contains("\"meta\""), "meta section exists");
        assertTrue(json.contains("\"issues\""), "issues array exists");
        assertTrue(json.contains("\"summary\""), "summary section exists");

        // meta.runtime.rps == 7
        assertTrue(
            json.matches("(?s).*\"runtime\"\\s*:\\s*\\{[^}]*\"rps\"\\s*:\\s*7[^}]*}.*"),
            "meta.runtime.rps should be 7"
        );

        // executiveSummary에 '7 RPS' 문구 포함
        assertTrue(
            json.contains("7 RPS"),
            "sections.executiveSummary should mention '7 RPS'"
        );
    }
}
