package com.webkillerai.core.service.export;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.IssueType;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class HtmlReportMinimalDomTest {

    @Test
    void exportsBasicHtmlWithExpectedSections() throws Exception {
        // given
        Path tempDir = Files.createTempDirectory("wk-htmltest-");
        ScanConfig cfg = new ScanConfig();
        cfg.setTarget("https://example.com");
        cfg.setMaxDepth(1);

        // ✅ 하드코딩 대신 프로젝트에 존재하는 아무 상수라도 선택
        IssueType anyType = pickAnyIssueType();

        VulnResult v1 = VulnResult.builder()
                .url(URI.create("https://example.com/a"))
                .issueType(anyType)
                .severity(Severity.MEDIUM)
                .description("Example issue A")
                .evidence("Example evidence A")
                .detectedAt(Instant.now())
                .riskScore(null)
                .build();

        VulnResult v2 = VulnResult.builder()
                .url(URI.create("https://example.com/b"))
                .issueType(anyType)
                .severity(Severity.HIGH)
                .description("Example issue B")
                .evidence("Example evidence B")
                .detectedAt(Instant.now())
                .riskScore(75)
                .build();

        List<VulnResult> results = List.of(v1, v2);

        HtmlReportExporter exporter = new HtmlReportExporter();
        String startedIso = Instant.now().toString();

        // when
        Path out = exporter.export(tempDir, cfg, results, startedIso);

        // then
        assertNotNull(out, "HTML export path must not be null");
        assertTrue(Files.exists(out), "HTML file should exist: " + out);

        String html = Files.readString(out, StandardCharsets.UTF_8);

        // 최소 DOM 스모크 어서션 (구조만 확인)
        assertTrue(html.contains("<table"), "table tag missing");
        assertTrue(html.contains("URL</th>"), "URL column header missing");
        assertTrue(html.contains("Type</th>"), "Type column header missing");
        assertTrue(html.contains("Severity</th>"), "Severity column header missing");
        assertTrue(html.contains("DetectedAt</th>"), "DetectedAt column header missing");

        // Summary/Risk 토큰(키워드 수준 체크)
        assertTrue(html.contains("Summary"), "Summary section missing");
        assertTrue(html.toLowerCase().contains("risk"), "Risk label missing");

        // Evidence 토글 힌트(구현 키워드가 다르면 여기만 조정)
        assertTrue(html.toLowerCase().contains("more"), "'More' toggle hint missing");
        assertTrue(html.toLowerCase().contains("less"), "'Less' toggle hint missing");
    }

    private static IssueType pickAnyIssueType() {
        IssueType[] values = IssueType.values();
        assertTrue(values.length > 0, "IssueType enum has no constants");
        return values[0]; // 아무거나 하나면 충분 (이 테스트는 타입명 자체가 중요하지 않음)
    }
}
