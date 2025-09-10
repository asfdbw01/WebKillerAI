package com.webkillerai.core.service.export;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public final class ReportNaming {

    public static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmm").withZone(ZoneId.systemDefault());

    public static ReportContext context(Path baseDir, String target, String startedIso) {
        Path out = (baseDir == null ? Paths.get("out") : baseDir);
        String host = extractHost(target);
        String slug = makeSlug(target);
        Instant started = parseIsoOrNow(startedIso);
        return new ReportContext(out, host, slug, started);
    }

    public static String timestamp(ReportContext ctx) { return TS_FMT.format(ctx.startedAt()); }
    public static Path reportsDir(ReportContext ctx) { return ctx.baseDir().resolve("reports").resolve(ctx.host()); }
    public static Path jsonPath(ReportContext ctx) { return reportsDir(ctx).resolve(filePrefix(ctx) + ".json"); }
    public static Path htmlPath(ReportContext ctx) { return reportsDir(ctx).resolve(filePrefix(ctx) + ".html"); }
    public static Path pdfPath (ReportContext ctx) { return reportsDir(ctx).resolve(filePrefix(ctx) + ".pdf"); }

    public static String filePrefix(ReportContext ctx) {
        return "scan-" + ctx.slug() + "-" + timestamp(ctx);
    }

    public record ReportContext(Path baseDir, String host, String slug, Instant startedAt) {}

    // ===== helpers =====
    private static Instant parseIsoOrNow(String iso) {
        try { return Instant.parse(iso); } catch (Exception ignore) { return Instant.now(); }
    }
    private static String extractHost(String target) {
        try {
            var u = URI.create(target);
            String h = u.getHost();
            return (h == null ? "unknown-host" : h.toLowerCase(Locale.ROOT)).replaceAll("[^a-z0-9._-]", "-");
        } catch (Exception e) { return "unknown-host"; }
    }
    private static String makeSlug(String url){
        if (url == null || url.isBlank()) return "no-url";
        String s = url.toLowerCase(Locale.ROOT).replaceFirst("^https?://", "");
        s = s.replaceAll("[^a-z0-9._/-]", "-").replaceAll("-{2,}", "-");
        if (s.length() > 60) s = s.substring(0, 60);
        return s.replace('/', '-').replaceAll("^-+|-+$", "");
    }
}
