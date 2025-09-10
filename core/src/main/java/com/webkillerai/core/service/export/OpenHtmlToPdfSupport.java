package com.webkillerai.core.service.export;

import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.helper.W3CDom;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public final class OpenHtmlToPdfSupport {

    private OpenHtmlToPdfSupport() {}

    public static boolean isAvailable() {
        try {
            Class.forName("com.openhtmltopdf.pdfboxout.PdfRendererBuilder");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    public static void htmlFileToPdf(Path htmlPath, Path pdfPath) {
        if (htmlPath == null || pdfPath == null) {
            throw new IllegalArgumentException("htmlPath/pdfPath is null");
        }
        try {
            Files.createDirectories(pdfPath.getParent());
        } catch (IOException e) {
            throw new RuntimeException("Cannot create PDF directory: " + pdfPath.getParent(), e);
        }

        try { Files.deleteIfExists(pdfPath); } catch (IOException ignore) {}

        String html;
        try {
            byte[] bytes = Files.readAllBytes(htmlPath);
            html = new String(bytes, StandardCharsets.UTF_8);
            if (!html.isEmpty() && html.charAt(0) == '\uFEFF') {
                html = html.substring(1);
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot read HTML: " + htmlPath, e);
        }

        String baseUri = htmlPath.getParent().toUri().toString();

        // Jsoup 파싱
        Document jdoc = Jsoup.parse(html, baseUri);
        if (jdoc.head().selectFirst("meta[charset]") == null) {
            jdoc.head().prepend("<meta charset=\"UTF-8\">");
        }
        // 🔴 폼/컨트롤 및 불필요 리소스 제거 (fast-mode NPE 회피)
        jdoc.select("form, input, button, select, textarea").remove();
        jdoc.select("script, link[rel=preload]").remove();

        org.w3c.dom.Document w3cDoc = new W3CDom().fromJsoup(jdoc);

        Path tmp = pdfPath.resolveSibling(pdfPath.getFileName().toString() + ".tmp");
        try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(
                tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE))) {

            PdfRendererBuilder builder = new PdfRendererBuilder();
            // 🔴 fast-mode 사용 금지 (문제 트리거)
            // builder.useFastMode();
            builder.withW3cDocument(w3cDoc, baseUri);

            // (선택) 한국어 폰트 리소스 추가하면 더 안정적입니다.
            // builder.useFont(() -> OpenHtmlToPdfSupport.class.getResourceAsStream("/fonts/NotoSansKR-Regular.otf"),
            //                 "Noto Sans KR");

            builder.toStream(os);
            builder.run();
            os.flush();

        } catch (Exception ex) {
            try { Files.deleteIfExists(tmp); } catch (IOException ignore) {}
            throw new RuntimeException("openhtmltopdf failed: " + ex.getMessage(), ex);
        }

        if (!isValidPdf(tmp)) {
            try { Files.deleteIfExists(tmp); } catch (IOException ignore) {}
            throw new RuntimeException("Produced PDF seems invalid (size/signature).");
        }
        try {
            Files.move(tmp, pdfPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            try { Files.deleteIfExists(tmp); } catch (IOException ignore) {}
            throw new RuntimeException("Failed to move temp PDF to final path: " + pdfPath, e);
        }
    }

    private static boolean isValidPdf(Path p) {
        try {
            if (p == null || !Files.exists(p)) return false;
            if (Files.size(p) < 100) return false;
            byte[] sig = new byte[5];
            try (var in = Files.newInputStream(p)) {
                int n = in.read(sig);
                if (n < 5) return false;
            }
            String s = new String(sig, StandardCharsets.US_ASCII);
            return s.startsWith("%PDF-");
        } catch (Exception e) {
            return false;
        }
    }
}
