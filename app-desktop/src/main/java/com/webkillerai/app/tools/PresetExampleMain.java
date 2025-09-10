package com.webkillerai.app.tools;

import com.webkillerai.app.ui.preset.AdvancedFilterPreset;
import com.webkillerai.app.ui.preset.AdvancedFilterPresetIO;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

public final class PresetExampleMain {
    public static void main(String[] args) throws Exception {
        // 출력 경로: 프로젝트 루트의 presets/ 폴더
        Path out = Path.of("presets/high-risk-xss-last7d.json");
        Files.createDirectories(out.getParent());

        AdvancedFilterPreset p = new AdvancedFilterPreset();
        p.v = "1";
        p.name = "High risk XSS (7d)";
        p.logic = "AND";
        p.types = List.of("XSS");
        p.severities = List.of("HIGH", "CRITICAL");
        p.urlContains = "login";
        p.evidenceContains = null;
        p.riskExpr = ">=75";
        p.dateFrom = Instant.now().minus(7, ChronoUnit.DAYS);
        p.dateTo   = Instant.now(); // UI에서는 exclusive 취급

        new AdvancedFilterPresetIO().exportToFile(p, out);
        System.out.println("Wrote preset: " + out.toAbsolutePath());
    }
}
