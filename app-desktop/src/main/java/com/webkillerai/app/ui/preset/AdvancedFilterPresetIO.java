package com.webkillerai.app.ui.preset;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.nio.file.Path;

public final class AdvancedFilterPresetIO {
    private final ObjectMapper om = new ObjectMapper()
            .registerModule(new JavaTimeModule())                                // ⬅️ 추가
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);            // ⬅️ 추가 (ISO-8601로)

    public void exportToFile(AdvancedFilterPreset preset, Path file) throws Exception {
        if (preset == null) throw new IllegalArgumentException("preset is null");
        om.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), preset);
    }

    public AdvancedFilterPreset importFromFile(Path file) throws Exception {
        AdvancedFilterPreset p = om.readValue(file.toFile(), AdvancedFilterPreset.class);
        if (!"1".equals(p.v)) {
            throw new IllegalArgumentException("Unsupported preset version: " + p.v);
        }
        return p;
    }
}

