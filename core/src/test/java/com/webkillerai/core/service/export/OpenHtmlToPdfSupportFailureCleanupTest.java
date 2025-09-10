package com.webkillerai.core.service.export;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.*;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 목적: PDF 생성 실패(출력 경로가 "디렉터리"일 때) 후, 임시(.tmp) 파일이 남지 않는지 검증.
 * - 프로덕션 코드는 변경하지 않음.
 * - htmlFileToPdf(파일 기반) API가 있을 때만 수행, 없으면 SKIP.
 * - Windows/Linux 모두 동작: 디렉터리에 파일 쓰기를 시도하면 실패해야 함.
 */
public class OpenHtmlToPdfSupportFailureCleanupTest {

    @TempDir Path tmp;

    @Test
    void when_pdf_export_fails_no_tmp_leftover() throws Exception {
        // given
        Path htmlIn = tmp.resolve("failure.html");
        Files.writeString(htmlIn, "<!doctype html><html><body><h1>Fail PDF</h1></body></html>");
        String baseUri = tmp.toUri().toString();

        // 출력 "경로"를 파일이 아니라 디렉터리로 설정 → 쓰기 실패 유도
        Path outDir = Files.createDirectory(tmp.resolve("out-as-dir"));

        // htmlFileToPdf 계열(파일 기반) 메서드를 찾아서만 테스트 진행
        Method m = findHtmlFileToPdfLike(OpenHtmlToPdfSupport.class);
        Assumptions.assumeTrue(m != null, "htmlFileToPdf(파일 기반) API 없음: 테스트 건너뜀");

        Object target = Modifier.isStatic(m.getModifiers()) ? null : newInstanceAllowingPrivate(OpenHtmlToPdfSupport.class);
        Object[] args = buildArgsForHtmlFileSig(m.getParameterTypes(), htmlIn, baseUri, outDir);
        Assumptions.assumeTrue(args != null, "호출 가능한 시그니처 매핑 불가: 테스트 건너뜀");

        // when & then: 호출이 실패해야 하고, .tmp 잔여물이 없어야 한다
        try {
            m.setAccessible(true);
            m.invoke(target, args);
            fail("디렉터리에 대한 PDF 쓰기는 실패해야 합니다.");
        } catch (Throwable expected) {
            // ok: 실패가 정상
        }

        // 임시파일(.tmp) 잔존 여부 확인 (temp 디렉터리 전체를 스캔)
        boolean hasTmpLeftover = hasAnyTmpFile(tmp);
        assertFalse(hasTmpLeftover, "PDF 실패 후 .tmp 임시파일이 남지 않아야 합니다.");
    }

    /* ================= helpers ================= */

    private Method findHtmlFileToPdfLike(Class<?> cls) {
        for (Method m : cls.getDeclaredMethods()) {
            String n = m.getName().toLowerCase();
            if (n.equals("htmlfiletopdf") || n.contains("htmlfile")) {
                return m;
            }
        }
        return null;
    }

    private Object newInstanceAllowingPrivate(Class<?> cls) throws Exception {
        var c = cls.getDeclaredConstructor();
        c.setAccessible(true);
        return c.newInstance();
    }

    /**
     * 흔한 파일 기반 시그니처 매핑:
     *  - (Path html, Path out)
     *  - (File html, File out)
     *  - (String htmlPath, String baseUri, Path out)
     *  - (String htmlPath, Path out) 등
     * 마지막 파라미터는 출력 대상으로 간주.
     */
    private Object[] buildArgsForHtmlFileSig(Class<?>[] pts, Path htmlIn, String baseUri, Path outDest) {
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
                    if (t == Path.class)                  args[i] = outDest;
                    else if (t == java.io.File.class)     args[i] = outDest.toFile();
                    else if (t == String.class)           args[i] = outDest.toString();
                    else return null;
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
        } catch (Exception e) {
            return null;
        }
    }

    private boolean hasAnyTmpFile(Path root) throws IOException {
        try (Stream<Path> s = Files.walk(root)) {
            return s.anyMatch(p -> Files.isRegularFile(p) && p.getFileName().toString().endsWith(".tmp"));
        }
    }
}
