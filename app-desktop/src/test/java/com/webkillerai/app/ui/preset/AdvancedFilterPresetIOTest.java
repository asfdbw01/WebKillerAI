package com.webkillerai.app.ui.preset;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AdvancedFilterPresetIOTest {

    @Test
    void roundTrip_export_then_import_preserves_fields() throws Exception {
        AdvancedFilterPresetIO io = new AdvancedFilterPresetIO();

        AdvancedFilterPreset p = new AdvancedFilterPreset();
        p.v = "1";
        p.name = "demo";
        p.logic = "AND";
        p.types = List.of("XSS", "SQLI");
        p.severities = List.of("HIGH", "CRITICAL");
        p.urlContains = "login";
        p.evidenceContains = null;
        p.riskExpr = ">=75";
        p.dateFrom = Instant.parse("2025-08-21T00:00:00Z");
        p.dateTo = null;

        Path tmp = Files.createTempFile("afp", ".json");
        try {
            io.exportToFile(p, tmp);
            AdvancedFilterPreset q = io.importFromFile(tmp);

            assertEquals("1", q.v);
            assertEquals(p.name, q.name);
            assertEquals(p.logic, q.logic);
            assertEquals(p.types, q.types);
            assertEquals(p.severities, q.severities);
            assertEquals(p.urlContains, q.urlContains);
            assertEquals(p.evidenceContains, q.evidenceContains);
            assertEquals(p.riskExpr, q.riskExpr);
            assertEquals(p.dateFrom, q.dateFrom);
            assertNull(q.dateTo);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    @Test
    void import_rejects_unsupported_version() throws Exception {
        Path tmp = Files.createTempFile("afp_badver", ".json");
        try {
            String badJson = """
                { "v": "99", "logic": "AND", "types": [], "severities": [] }
                """;
            Files.writeString(tmp, badJson);
            AdvancedFilterPresetIO io = new AdvancedFilterPresetIO();
            assertThrows(IllegalArgumentException.class, () -> io.importFromFile(tmp));
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
