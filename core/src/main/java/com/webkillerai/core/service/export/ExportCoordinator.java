package com.webkillerai.core.service.export;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.service.ScanService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.webkillerai.core.service.export.ReportNaming.*;

public final class ExportCoordinator {

    private static final Logger LOG = Logger.getLogger(ExportCoordinator.class.getName());

    private final JsonReportExporter json = new JsonReportExporter();
    private final HtmlReportExporter html = new HtmlReportExporter();
    private final PdfReportExporter  pdf  = new PdfReportExporter(); // 있을 때만 사용

    // UI 체크박스 값(null 허용)
    private Boolean uiAlsoJsonToggle = null;

    /** 필요 시 런타임 통계 주입 */
    public ExportCoordinator withRuntime(ScanService svc) {
        json.withRuntime(svc);
        return this;
    }

    /** UI 체크박스 값 주입 (체이닝) */
    public ExportCoordinator withAlsoJsonToggle(Boolean toggle) {
        this.uiAlsoJsonToggle = toggle;
        return this;
    }

    /** formats: 소문자 {"json","html","pdf"} */
    public Path exportAll(Path baseDir,
                          ScanConfig cfg,
                          java.util.List<VulnResult> results,
                          String startedIso,
                          Set<String> formats) throws Exception {
        Objects.requireNonNull(cfg, "cfg");
        var ctx = ReportNaming.context(baseDir, cfg.getTarget(), startedIso);
        Files.createDirectories(reportsDir(ctx));

        final boolean wantJson = formats.contains("json");
        final boolean wantHtml = formats.contains("html");
        final boolean wantPdf  = formats.contains("pdf");

        final boolean openHtmlAvail = OpenHtmlToPdfSupport.isAvailable();
        final boolean pdfExporterAvail = PdfReportExporter.isAvailable(); // 내부에서 안전 처리됨

        // 계획 로그
        LOG.info(() -> "[Export plan] wantJson=" + wantJson +
                ", wantHtml=" + wantHtml +
                ", wantPdf=" + wantPdf +
                ", openhtmltopdf=" + openHtmlAvail +
                ", PdfReportExporter=" + pdfExporterAvail);

        // 우선순위: UI > SysProp(-Dwk.export.alsoJson) > scan.yml(output.alsoJson)
        boolean alsoJson = resolveAlsoJson(uiAlsoJsonToggle, cfg);

        Path last = null;
        Path htmlPath = null;

        // JSON
        if (wantJson) {
            last = json.export(baseDir, cfg, results, startedIso);
        }

        // HTML
        if (wantHtml) {
            htmlPath = html.export(baseDir, cfg, results, startedIso);
            last = htmlPath;
        }

        // PDF
        if (wantPdf) {
            try {
                // 1) openhtmltopdf 경로
                if (openHtmlAvail) {
                    htmlPath = ensureHtml(htmlPath, baseDir, cfg, results, startedIso);
                    Path pdfPath = changeExt(htmlPath, ".pdf");

                    // 내부에서 임시파일→검증→원자적 이동. 실패 시 예외 + 산출물 삭제.
                    OpenHtmlToPdfSupport.htmlFileToPdf(htmlPath, pdfPath);

                    // (중복 방지지만, 혹시 모를 외부 개입 대비) 한 번 더 가볍게 검사
                    if (!isValidPdf(pdfPath)) {
                        safeDelete(pdfPath);
                        throw new RuntimeException("PDF invalid after openhtmltopdf post-check.");
                    }

                    LOG.info(() -> "PDF exported (openhtmltopdf): " + pdfPath.toAbsolutePath());
                    last = pdfPath;
                }
                // 2) 폴백: PdfReportExporter
                else if (pdfExporterAvail) {
                    Path p = tryPdfFallbackValidated(baseDir, cfg, results, startedIso);
                    if (p != null) last = p;
                    else LOG.warning("PdfReportExporter fallback produced no valid PDF.");
                }
                // 3) 둘 다 불가
                else {
                    LOG.warning("No usable PDF renderer. Skip PDF export.");
                }
            } catch (Throwable t) {
                LOG.log(Level.WARNING, "PDF export failed on primary path. Trying fallback if possible.", t);

                // openhtmltopdf 실패 시 폴백
                if (!openHtmlAvail && pdfExporterAvail) {
                    // 이미 위에서 처리했으니 여기선 도달 안함. 안전차원에서 재확인.
                    Path p = tryPdfFallbackValidated(baseDir, cfg, results, startedIso);
                    if (p != null) last = p;
                } else if (pdfExporterAvail) {
                    Path p = tryPdfFallbackValidated(baseDir, cfg, results, startedIso);
                    if (p != null) last = p;
                }
                // 폴백까지 실패해도 전체는 계속 진행
            }
        }

        // “Also save JSON”
        if (alsoJson && !wantJson) {
            last = json.export(baseDir, cfg, results, startedIso);
        }

        // 아무것도 못 만들었으면 최소 JSON
        if (last == null) {
            last = json.export(baseDir, cfg, results, startedIso);
        }
        return last;
    }

    // ---------- helpers ----------

    /** HTML 경로가 없으면 생성하여 반환 */
    private Path ensureHtml(Path htmlPath,
                            Path baseDir,
                            ScanConfig cfg,
                            java.util.List<VulnResult> results,
                            String startedIso) throws Exception {
        if (htmlPath != null) return htmlPath;
        return html.export(baseDir, cfg, results, startedIso);
    }

    /** PdfReportExporter 폴백 시도 + 결과 PDF 유효성 검증 */
    private Path tryPdfFallbackValidated(Path baseDir,
                                         ScanConfig cfg,
                                         java.util.List<VulnResult> results,
                                         String startedIso) {
        try {
            if (!PdfReportExporter.isAvailable()) return null;

            Path out = pdf.export(baseDir, cfg, results, startedIso);
            if (!isValidPdf(out)) {
                LOG.warning("PdfReportExporter produced invalid PDF (0KB or bad header): " + out);
                safeDelete(out);
                return null;
            }

            LOG.info("PDF exported (PdfReportExporter): " + out.toAbsolutePath());
            return out;

        } catch (Throwable ex) {
            LOG.log(Level.WARNING, "PdfReportExporter export failed.", ex);
            return null;
        }
    }

    private static Path changeExt(Path htmlPath, String newExt) {
        String name = htmlPath.getFileName().toString();
        String replaced = name.replaceFirst("\\.html?$", "") + newExt;
        return htmlPath.resolveSibling(replaced);
    }

    /** last가 null이면 최소 JSON을 만들어 반환값 보장. */
    private Path ensureAtLeastJson(Path last,
                                   Path baseDir,
                                   ScanConfig cfg,
                                   java.util.List<VulnResult> results,
                                   String startedIso) {
        if (last != null) return last;
        try {
            return json.export(baseDir, cfg, results, startedIso);
        } catch (Exception e) {
            LOG.log(Level.WARNING, "ensureAtLeastJson() JSON export failed.", e);
            return null;
        }
    }

    // -------- 우선순위 해석: UI > SysProp > YAML(output.alsoJson) --------
    private static boolean resolveAlsoJson(Boolean uiToggle, ScanConfig cfg) {
        if (uiToggle != null) return uiToggle; // UI 최우선

        String p = System.getProperty("wk.export.alsoJson");   // -Dwk.export.alsoJson=true
        if (p != null) return Boolean.parseBoolean(p);

        // 마지막으로 scan.yml의 output.alsoJson 시도 (리플렉션 기반, 없으면 false)
        return readAlsoJsonFromCfg(cfg);
    }

    // output.alsoJson을 리플렉션으로 안전하게 읽는다.
    private static boolean readAlsoJsonFromCfg(ScanConfig cfg) {
        try {
            Object out = cfg.getClass().getMethod("getOutput").invoke(cfg);
            if (out == null) return false;
            try {
                Object v = out.getClass().getMethod("isAlsoJson").invoke(out);
                if (v instanceof Boolean b) return b;
            } catch (NoSuchMethodException ignore) {
                Object v2 = out.getClass().getMethod("getAlsoJson").invoke(out);
                if (v2 instanceof Boolean b2) return b2;
            }
        } catch (Exception ignore) { /* YAML에 없거나 필드 미존재 시 false */ }
        return false;
    }

    // ===== 유틸: PDF 유효성/삭제 =====
    private static boolean isValidPdf(Path p) {
        try {
            if (p == null || !Files.exists(p)) return false;
            if (Files.size(p) < 100) return false;           // 0KB/극소 파일 방지
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

    private static void safeDelete(Path p) {
        try { if (p != null) Files.deleteIfExists(p); } catch (Exception ignore) {}
    }
}
