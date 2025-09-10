package com.webkillerai.app.ui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

/** AdvancedFilter 프리셋 파일 Import/Export 유틸 (.wkaf.json 권장) */
final class AdvancedFilterPresetIO {
    private AdvancedFilterPresetIO() {}

    /** 프리셋 JSON을 지정 파일로 저장 (UTF-8) */
    static void exportToFile(String json, Path path) throws IOException {
        Objects.requireNonNull(json, "json");
        Objects.requireNonNull(path, "path");
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }
        Files.writeString(
                path,
                json,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        );
    }

    /** 프리셋 JSON을 지정 파일에서 로드 (UTF-8) */
    static String importFromFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        return Files.readString(path, StandardCharsets.UTF_8);
    }
}
