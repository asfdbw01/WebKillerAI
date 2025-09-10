package com.webkillerai.core.service.export;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class OpenHtmlToPdfSupportSmokeTest {

    @TempDir Path tmp;

    @Test
    void pdf_is_non_empty_and_has_signature() throws Exception {
        // given
        String html = "<!doctype html><html><head><meta charset='UTF-8'><title>T</title></head>"
                    + "<body><h1>PDF Smoke</h1><p>안녕하세요 WebKillerAI.</p></body></html>";
        String baseUri = tmp.toUri().toString();
        Path htmlIn = tmp.resolve("smoke.html");
        Path out = tmp.resolve("smoke.pdf");
        Files.writeString(htmlIn, html);

        // when
        Class<?> cls = OpenHtmlToPdfSupport.class;
        boolean invoked = tryHtmlFileMethod(cls, htmlIn, baseUri, out);
        if (!invoked) {
            // 파일 기반 메서드가 없을 때만 fallback(문자열/스트림 기반)
            invoked = tryFlexibleMethod(cls, html, baseUri, out);
        }

        // then
        assertTrue(invoked, "OpenHtmlToPdfSupport에서 PDF 생성 메서드를 찾지 못했습니다.");
        assertTrue(Files.exists(out), "최종 PDF 파일이 존재해야 함");
        long size = Files.size(out);
        assertTrue(size > 0, "최종 PDF 크기는 0보다 커야 함(0KB 방지)");
        assertTrue(startsWithPdfSignature(out), "파일이 '%PDF-' 시그니처로 시작해야 함");

        try (var s = Files.list(tmp)) {
            boolean hasTmp = s.anyMatch(p -> p.getFileName().toString().endsWith(".tmp"));
            assertFalse(hasTmp, "임시(.tmp) 파일이 남지 않아야 함");
        }
    }

    /* ---------- 1) HTML 파일 → PDF 메서드 먼저 시도 ---------- */
    private boolean tryHtmlFileMethod(Class<?> cls, Path htmlIn, String baseUri, Path out) throws Exception {
        // 이름에 'htmlfile' 또는 정확히 'htmlFileToPdf'가 들어간 메서드 우선
        Method[] methods = cls.getDeclaredMethods();
        for (Method m : methods) {
            String n = m.getName().toLowerCase();
            if (!(n.contains("htmlfile") || n.equals("htmlfiletopdf"))) continue;

            Class<?>[] p = m.getParameterTypes();
            Object target = Modifier.isStatic(m.getModifiers()) ? null : newInstanceAllowingPrivate(cls);
            Object[] args = buildArgsForHtmlFileSig(p, htmlIn, baseUri, out);
            if (args == null) continue;

            m.setAccessible(true);
            m.invoke(target, args);
            return true;
        }
        return false;
    }

    private Object[] buildArgsForHtmlFileSig(Class<?>[] pts, Path htmlIn, String baseUri, Path out) {
        // 흔한 시그니처들:
        // (Path html, Path out), (java.io.File html, java.io.File out),
        // (String htmlPath, String baseUri, Path out) 등
        try {
            Object[] args = new Object[pts.length];
            for (int i = 0; i < pts.length; i++) {
                Class<?> t = pts[i];
                // 첫 파라미터는 HTML 입력으로 가정
                if (i == 0) {
                    if (t == Path.class)                  args[i] = htmlIn;
                    else if (t == java.io.File.class)     args[i] = htmlIn.toFile();
                    else if (t == String.class)           args[i] = htmlIn.toString();
                    else return null;
                    continue;
                }
                // 마지막 파라미터는 출력 PDF로 가정
                if (i == pts.length - 1) {
                    if (t == Path.class)                  args[i] = out;
                    else if (t == java.io.File.class)     args[i] = out.toFile();
                    else if (t == String.class)           args[i] = out.toString();
                    else if (OutputStream.class.isAssignableFrom(t)) {
                        // 드물지만 출력이 스트림인 경우
                        args[i] = Files.newOutputStream(out);
                    } else return null;
                    continue;
                }
                // 중간 파라미터는 baseUri/옵션 등으로 처리
                if (t == String.class)                   args[i] = baseUri;
                else if (t == java.net.URI.class)        args[i] = java.net.URI.create(baseUri);
                else if (t == boolean.class || t == Boolean.class) args[i] = Boolean.TRUE;
                else if (t == int.class || t == Integer.class)     args[i] = 0;
                else if (t == long.class || t == Long.class)       args[i] = 0L;
                else return null;
            }
            return args;
        } catch (IOException e) {
            return null;
        }
    }

    /* ---------- 2) 문자열/스트림 기반 유연 메서드 시도 ---------- */
    private boolean tryFlexibleMethod(Class<?> cls, String html, String baseUri, Path out) throws Exception {
        // (정적 → 인스턴스 순서)
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
                // 이름 휴리스틱: pdf/render/export/write 포함
                if (!(n.contains("pdf") || n.contains("render") || n.contains("export") || n.contains("write")))
                    continue;
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
            // 매핑 불가
            return null;
        }
        return boundOut ? args : null;
    }

    /* ---------- 인스턴스 생성 유틸(비공개 생성자 허용) ---------- */
    private Object newInstanceAllowingPrivate(Class<?> cls) throws Exception {
        Constructor<?> c = cls.getDeclaredConstructor();
        c.setAccessible(true);
        return c.newInstance();
    }

    /* ---------- PDF 시그니처 확인 ---------- */
    private boolean startsWithPdfSignature(Path pdf) throws IOException {
        byte[] head = new byte[5];
        try (var in = Files.newInputStream(pdf)) {
            int n = in.read(head);
            if (n < 5) return false;
        }
        return head[0]=='%' && head[1]=='P' && head[2]=='D' && head[3]=='F' && head[4]=='-';
    }
}
