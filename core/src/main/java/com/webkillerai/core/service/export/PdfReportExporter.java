package com.webkillerai.core.service.export;

import static com.webkillerai.core.service.export.ReportNaming.*;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * PDF 리포트 Exporter (옵션)
 * - openhtmltopdf를 "리플렉션"으로 호출 → 의존성 없으면 친절히 실패
 * - HTML을 먼저 생성한 뒤 그 내용을 PDF로 변환
 * 출력: out/reports/<host>/scan-<slug>-<timestamp>.pdf
 */
public class PdfReportExporter implements ReportExporter {

    /** 라이브러리(classpath) 존재 여부 */
    public static boolean isAvailable() {
        try {
            Class.forName("com.openhtmltopdf.pdfboxout.PdfRendererBuilder");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    @Override
    public Path export(Path baseDir, ScanConfig cfg, List<VulnResult> results, String startedIso) throws Exception {
        if (!isAvailable()) {
            throw new IllegalStateException("""
                PDF exporter requires OpenHTMLtoPDF on classpath.
                Add to core/build.gradle:
                  implementation 'com.openhtmltopdf:openhtmltopdf-pdfbox:1.0.10'
                  implementation 'com.openhtmltopdf:openhtmltopdf-slf4j:1.0.10'
                """);
        }

        Objects.requireNonNull(cfg, "cfg");
        final Path outRoot = (baseDir != null) ? baseDir : Paths.get("out");

        // 1) HTML 먼저 생성 (HTML 내 evidence 표시 여부는 HtmlReportExporter가 시스템 프로퍼티로 제어)
        Path htmlPath = new HtmlReportExporter().export(outRoot, cfg, results, startedIso);
        String html = Files.readString(htmlPath, StandardCharsets.UTF_8);

        // 2) ReportNaming으로 PDF 경로 산출(HTML/JSON과 동일한 host/slug/timestamp)
        var ctx = context(outRoot, cfg.getTarget(), startedIso);
        Files.createDirectories(reportsDir(ctx));
        Path pdf = pdfPath(ctx);

        // 3) openhtmltopdf (리플렉션) 호출
        Class<?> builderCls = Class.forName("com.openhtmltopdf.pdfboxout.PdfRendererBuilder");
        Object builder = builderCls.getConstructor().newInstance();

        var withHtmlContent = builderCls.getMethod("withHtmlContent", String.class, String.class);
        var toStream        = builderCls.getMethod("toStream", java.io.OutputStream.class);
        var run             = builderCls.getMethod("run");

        String baseUrl = htmlPath.getParent().toUri().toString(); // 리소스 해석용
        withHtmlContent.invoke(builder, html, baseUrl);
        try (OutputStream os = Files.newOutputStream(pdf, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            toStream.invoke(builder, os);
            run.invoke(builder);
        }

        return pdf;
    }
}
