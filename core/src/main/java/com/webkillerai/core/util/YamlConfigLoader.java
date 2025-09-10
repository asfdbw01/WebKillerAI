package com.webkillerai.core.util;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Mode;                         // 외부 enum Mode
import com.webkillerai.core.model.ScanConfig.OutputFormat;     // 내부 enum OutputFormat
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

/**
 * 루트 scan.yml을 읽어 ScanConfig로 변환.
 *
 * 예상 YAML 키:
 * target: "https://example.com"
 * sameDomainOnly: true
 * mode: SAFE | SAFE_PLUS | AGGRESSIVE_LITE
 * timeoutMs: 10000
 * concurrency: 4
 * followRedirects: true
 * scope:
 *   maxDepth: 2
 * output:
 *   dir: "out"
 *   format: "json"
 * rps: 10
 *
 * # SAFE_PLUS 튜닝(옵션)
 * maxParamsPerUrl: 3
 * xssParamHints: ["q","search","s"]
 * sqliParamHints: ["id","uid","user"]
 *
 * # 크롤러(옵션)
 * crawler:
 *   respectRobots: true
 *   cacheTtlMinutes: 30
 *
 * # AGGRESSIVE_LITE(옵션)
 * aggressive:
 *   maxParamsPerUrl: 3
 *   runTimeBudgetMs: 60000
 *   enableOpenRedirect: true
 *   enablePathTraversal: true
 *   enableSSTI: true
 *   enableMixedContent: true
 */
public final class YamlConfigLoader {

    private YamlConfigLoader() {}

    public static ScanConfig loadDefault() throws IOException {
        return load(Path.of("scan.yml"));
    }

    public static ScanConfig load(Path yamlPath) throws IOException {
        Objects.requireNonNull(yamlPath, "yamlPath");
        if (!Files.exists(yamlPath)) {
            throw new IOException("scan.yml not found at: " + yamlPath.toAbsolutePath());
        }
        try (InputStream in = Files.newInputStream(yamlPath)) {
            LoaderOptions opts = new LoaderOptions();
            Yaml yaml = new Yaml(new SafeConstructor(opts));
            Object root = yaml.load(in);

            ScanConfig cfg = ScanConfig.defaults();

            if (!(root instanceof Map<?, ?> map)) {
                // 비어있거나 단순 스칼라면 defaults 유지
                cfg.validate();
                return cfg;
            }

            // 1) 평면 키
            setString(map, "target", cfg::setTarget);
            setBoolean(map, "sameDomainOnly", cfg::setSameDomainOnly);
            setEnum(map, "mode", Mode.class, cfg::setMode);
            setIntAsDurationMs(map, "timeoutMs", cfg::setTimeout);
            setInt(map, "concurrency", cfg::setConcurrency);
            setBoolean(map, "followRedirects", cfg::setFollowRedirects);
            setInt(map, "rps", cfg::setRps);

            // SAFE_PLUS 튜닝 키(옵션)
            setInt(map, "maxParamsPerUrl", cfg::setMaxParamsPerUrl);
            setStringList(map, "xssParamHints", cfg::setXssParamHints);
            setStringList(map, "sqliParamHints", cfg::setSqliParamHints);

            // 2) scope.maxDepth
            Map<String, Object> scope = getMap(map, "scope");
            if (scope != null) {
                setInt(scope, "maxDepth", cfg::setMaxDepth);
            }

            // 3) output.dir / output.format
            Map<String, Object> output = getMap(map, "output");
            if (output != null) {
                setPath(output, "dir", cfg::setOutputDir);
                setEnum(output, "format", OutputFormat.class, cfg::setOutputFormat);
            }

            // 4) crawler.*
            Map<String, Object> crawler = getMap(map, "crawler");
            if (crawler != null) {
                var c = cfg.getCrawler();
                setBoolean(crawler, "respectRobots", c::setRespectRobots);
                setInt(crawler, "cacheTtlMinutes", c::setCacheTtlMinutes);
            }

            // 5) aggressive.* (AGGRESSIVE_LITE 선반영)
            Map<String, Object> ag = getMap(map, "aggressive");
            if (ag != null) {
                setInt(ag, "maxParamsPerUrl", i -> cfg.aggressive().setMaxParamsPerUrl(i));
                setInt(ag, "runTimeBudgetMs", i -> cfg.aggressive().setRunTimeBudgetMs(i));
                setBoolean(ag, "enableOpenRedirect", b -> cfg.aggressive().setEnableOpenRedirect(b));
                setBoolean(ag, "enablePathTraversal", b -> cfg.aggressive().setEnablePathTraversal(b));
                setBoolean(ag, "enableSSTI", b -> cfg.aggressive().setEnableSSTI(b));
                setBoolean(ag, "enableMixedContent", b -> cfg.aggressive().setEnableMixedContent(b));
            }

            // 기본값/필수값 확인
            cfg.validate();
            return cfg;
        }
    }

    // ------------ helpers ------------
    @SuppressWarnings("unchecked")
    private static Map<String, Object> getMap(Map<?, ?> map, String key) {
        Object v = map.get(key);
        if (v instanceof Map<?, ?> m) return (Map<String, Object>) m;
        return null;
    }

    private static void setString(Map<?, ?> map, String key, Consumer<String> setter) {
        Object v = map.get(key);
        if (v != null) setter.accept(String.valueOf(v));
    }

    private static void setStringList(Map<?, ?> map, String key, Consumer<List<String>> setter) {
        Object v = map.get(key);
        if (v == null) return;
        if (v instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object o : list) if (o != null) out.add(String.valueOf(o));
            if (!out.isEmpty()) setter.accept(List.copyOf(out));
            return;
        }
        // "a,b,c" 형태 지원
        String s = String.valueOf(v).trim();
        if (!s.isEmpty()) {
            String[] parts = s.split("\\s*,\\s*");
            List<String> out = new ArrayList<>();
            for (String p : parts) if (!p.isEmpty()) out.add(p);
            if (!out.isEmpty()) setter.accept(List.copyOf(out));
        }
    }

    private static void setBoolean(Map<?, ?> map, String key, Consumer<Boolean> setter) {
        Object v = map.get(key);
        if (v instanceof Boolean b) setter.accept(b);
        else if (v != null) setter.accept(Boolean.parseBoolean(String.valueOf(v)));
    }

    private static void setInt(Map<?, ?> map, String key, IntConsumer setter) {
        Object v = map.get(key);
        if (v instanceof Number n) setter.accept(n.intValue());
        else if (v != null) setter.accept(Integer.parseInt(String.valueOf(v)));
    }

    private static void setIntAsDurationMs(Map<?, ?> map, String key, Consumer<Duration> setter) {
        Object v = map.get(key);
        if (v == null) return;
        long ms = (v instanceof Number n) ? n.longValue() : Long.parseLong(String.valueOf(v));
        if (ms > 0) setter.accept(Duration.ofMillis(ms));
    }

    private static void setPath(Map<?, ?> map, String key, Consumer<Path> setter) {
        Object v = map.get(key);
        if (v != null) setter.accept(Path.of(String.valueOf(v)));
    }

    private static <E extends Enum<E>> void setEnum(Map<?, ?> map, String key, Class<E> type, Consumer<E> setter) {
        Object v = map.get(key);
        if (v == null) return;
        String s = String.valueOf(v).trim();
        for (E e : type.getEnumConstants()) {
            if (e.name().equalsIgnoreCase(s)) {
                setter.accept(e);
                return;
            }
        }
        try {
            setter.accept(Enum.valueOf(type, s.toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignore) {
            // 무시(사용자 오타 시 기본값 유지)
        }
    }
}
