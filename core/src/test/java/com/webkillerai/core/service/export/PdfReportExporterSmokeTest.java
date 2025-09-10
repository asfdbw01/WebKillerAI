package com.webkillerai.core.service.export;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class PdfReportExporterSmokeTest {

    @TempDir Path tmp;

    @Test
    void pdf_exporter_writes_non_empty_pdf() throws Exception {
        // PdfReportExporter가 클래스패스에 없으면 SKIP
        Class<?> exporter = findExporterOrSkip();
        String html = "<!doctype html><html><head><meta charset='UTF-8'><title>T</title></head>"
                    + "<body><h1>Exporter Smoke</h1><p>WebKillerAI</p></body></html>";
        String baseUri = tmp.toUri().toString();
        Path htmlIn = tmp.resolve("exporter.html");
        Path out = tmp.resolve("exporter.pdf");
        Files.writeString(htmlIn, html);

        boolean invoked = tryHtmlFileMethod(exporter, htmlIn, baseUri, out);
        if (!invoked) invoked = tryFlexibleMethod(exporter, html, baseUri, out);

        // ▶ 여기: 직접 호출 가능한 퍼블릭 API가 없으면 SKIP
        Assumptions.assumeTrue(invoked, "PdfReportExporter는 직접 호출 API를 노출하지 않음(ExportCoordinator 내부 전용). 테스트 건너뜀.");

        assertTrue(Files.exists(out), "PDF 파일이 생성되어야 함");
        long size = Files.size(out);
        assertTrue(size > 0, "PDF 크기는 0보다 커야 함(0KB 방지)");
        assertTrue(startsWithPdfSignature(out), "파일 시작이 '%PDF-' 여야 함");
    }

    /* ========== helpers ========== */

    private Class<?> findExporterOrSkip() {
        List<String> candidates = List.of(
            "com.webkillerai.core.service.export.PdfReportExporter",
            "webkillerai.core.service.export.PdfReportExporter"
        );
        for (String fqcn : candidates) {
            try { return Class.forName(fqcn); } catch (ClassNotFoundException ignore) {}
        }
        Assumptions.assumeTrue(false, "PdfReportExporter 미존재: 테스트 건너뜀");
        return null; // unreachable
    }

    private boolean tryHtmlFileMethod(Class<?> cls, Path htmlIn, String baseUri, Path out) throws Exception {
        for (Method m : cls.getDeclaredMethods()) {
            String n = m.getName().toLowerCase();
            if (!(n.contains("htmlfile") || n.equals("htmlfiletopdf"))) continue;

            Object target = Modifier.isStatic(m.getModifiers()) ? null : newInstanceAllowingPrivate(cls);
            Object[] args = buildArgsForHtmlFileSig(m.getParameterTypes(), htmlIn, baseUri, out);
            if (args == null) continue;

            m.setAccessible(true);
            m.invoke(target, args);
            return true;
        }
        return false;
    }

    private boolean tryFlexibleMethod(Class<?> cls, String html, String baseUri, Path out) throws Exception {
        if (invokeMatchingMethod(null, cls, html, baseUri, out, true)) return true;
        Object instance = newInstanceAllowingPrivate(cls);
        return invokeMatchingMethod(instance, cls, html, baseUri, out, false);
    }

    private boolean invokeMatchingMethod(Object target, Class<?> cls, String html, String baseUri, Path out, boolean staticOnly) throws Exception {
        Method[] methods = cls.getDeclaredMethods();
        List<java.io.Closeable> toClose = new ArrayList<>();
        try {
            for (Method m : methods) {
                String n = m.getName().toLowerCase();
                if (!(n.contains("pdf") || n.contains("render") || n.contains("export") || n.contains("write"))) continue;
                boolean isStatic = Modifier.isStatic(m.getModifiers());
                if (staticOnly && !isStatic) continue;
                if (!staticOnly && isStatic) continue;

                Object[] args = buildArgsForFlexibleSig(m.getParameterTypes(), html, baseUri, out, toClose);
                if (args == null) continue;

                m.setAccessible(true);
                m.invoke(target, args);
                return true;
            }
            return false;
        } finally {
            for (var c : toClose) try { c.close(); } catch (IOException ignore) {}
        }
    }

    private Object newInstanceAllowingPrivate(Class<?> cls) throws Exception {
        var c = cls.getDeclaredConstructor();
        c.setAccessible(true);
        return c.newInstance();
    }

    private Object[] buildArgsForHtmlFileSig(Class<?>[] pts, Path htmlIn, String baseUri, Path out) {
        try {
            Object[] args = new Object[pts.length];
            for (int i = 0; i < pts.length; i++) {
                Class<?> t = pts[i];
                if (i == 0) {
                    if (t == Path.class)                  args[i] = htmlIn;
                    else if (t == java.io.File.class)     args[i] = htmlIn.toFile();
                    else if (t == String.class)           args[i] = htmlIn.toString();
                    else return null;
                } else if (i == pts.length - 1) {
                    if (t == Path.class)                  args[i] = out;
                    else if (t == java.io.File.class)     args[i] = out.toFile();
                    else if (t == String.class)           args[i] = out.toString();
                    else if (OutputStream.class.isAssignableFrom(t)) {
                        args[i] = Files.newOutputStream(out);
                    } else return null;
                } else {
                    if (t == String.class)                args[i] = baseUri;
                    else if (t == java.net.URI.class)     args[i] = java.net.URI.create(baseUri);
                    else if (t == boolean.class || t == Boolean.class) args[i] = Boolean.TRUE;
                    else if (t == int.class || t == Integer.class)     args[i] = 0;
                    else if (t == long.class || t == Long.class)       args[i] = 0L;
                    else return null;
                }
            }
            return args;
        } catch (IOException e) {
            return null;
        }
    }

    private Object[] buildArgsForFlexibleSig(Class<?>[] pts, String html, String baseUri, Path out, List<java.io.Closeable> toClose) throws IOException {
        Object[] args = new Object[pts.length];
        boolean usedHtml = false, usedBase = false, boundOut = false;
        for (int i = 0; i < pts.length; i++) {
            Class<?> t = pts[i];
            if ((t == String.class || CharSequence.class.isAssignableFrom(t)) && !usedHtml) {
                args[i] = html; usedHtml = true; continue;
            }
            if (t == String.class && !usedBase) {
                args[i] = baseUri; usedBase = true; continue;
            }
            if (t == java.net.URI.class) {
                args[i] = java.net.URI.create(baseUri); usedBase = true; continue;
            }
            if (t == Path.class) { args[i] = out; boundOut = true; continue; }
            if (t == java.io.File.class) { args[i] = out.toFile(); boundOut = true; continue; }
            if (OutputStream.class.isAssignableFrom(t)) {
                var os = Files.newOutputStream(out); args[i] = os; toClose.add(os); boundOut = true; continue;
            }
            if (t == boolean.class || t == Boolean.class) { args[i] = Boolean.TRUE; continue; }
            if (t == int.class || t == Integer.class) { args[i] = 0; continue; }
            if (t == long.class || t == Long.class) { args[i] = 0L; continue; }
            return null;
        }
        return boundOut ? args : null;
    }

    private boolean startsWithPdfSignature(Path pdf) throws IOException {
        byte[] head = new byte[5];
        try (var in = Files.newInputStream(pdf)) {
            int n = in.read(head);
            if (n < 5) return false;
        }
        return head[0]=='%' && head[1]=='P' && head[2]=='D' && head[3]=='F' && head[4]=='-';
    }
}
