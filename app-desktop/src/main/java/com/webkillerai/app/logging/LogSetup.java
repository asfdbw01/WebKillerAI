package com.webkillerai.app.logging;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.*;
import java.util.Locale;
import java.util.prefs.Preferences;
import java.util.logging.*;

/**
 * java.util.logging 전역 설정 + 사이즈 롤링(기본 2MB x 5)
 * - configure(outRoot): outRoot/logs 기준 초기화
 * - init(logDir): logs 디렉터리를 직접 넘겨 초기화
 * - setLevel(Level, save): 루트/핸들러 레벨 즉시 변경(+옵션: Preferences 저장)
 * - getSavedLevel(): 마지막 저장 레벨 반환(없으면 -Dwk.log.level 또는 INFO)
 */
public final class LogSetup {
    private LogSetup() {}

    private static volatile boolean initialized = false; // 재초기화 방지
    private static final Formatter LINE_FORMATTER = new LineFormatter(); // 단일 인스턴스

    // UI 복원을 위한 Preferences 키
    private static final String PREF_NODE = "webkillerai";
    private static final String PREF_KEY_LEVEL = "log.level";

    /** outRoot/logs/app-%g.log 로 저장. System props:
     *  -Dwk.log.level=FINE|INFO|WARNING|SEVERE
     *  -Dwk.log.sizeMb=2
     *  -Dwk.log.files=5
     *  -Dwk.log.console=true|false (기본 true)
     */
    public static synchronized void configure(Path outRoot) {
        init(outRoot.resolve("logs"));
    }

    /** logs 디렉터리를 직접 넘겨 초기화 */
    public static synchronized void init(Path logDir) {
        if (initialized) return;
        initialized = true;

        try {
            Files.createDirectories(logDir);

            // 초기 레벨: Preferences → -Dwk.log.level → INFO
            Level level = resolveInitialLevel();

            int sizeMb   = parseInt(System.getProperty("wk.log.sizeMb"), 2);
            int fileCnt  = parseInt(System.getProperty("wk.log.files"), 5);
            boolean toConsole = !"false".equalsIgnoreCase(System.getProperty("wk.log.console", "true"));

            // 루트 로거 초기화
            LogManager.getLogManager().reset();
            Logger root = Logger.getLogger("");

            // 콘솔
            if (toConsole) {
                ConsoleHandler console = new ConsoleHandler();
                console.setLevel(level);
                console.setFormatter(LINE_FORMATTER);
                root.addHandler(console);
            }

            // 파일(롤링)
            String pattern = logDir.resolve("app-%g.log").toString();
            FileHandler file = new FileHandler(pattern, sizeMb * 1024 * 1024, fileCnt, true);
            file.setLevel(level);
            file.setFormatter(LINE_FORMATTER);
            root.addHandler(file);

            // 루트 레벨
            root.setLevel(level);

            // 부팅 로그
            Logger.getLogger(LogSetup.class.getName()).log(level,
                    () -> "Log initialized. dir=" + logDir.toAbsolutePath() + ", level=" + level.getName());

        } catch (IOException e) {
            // 마지막 보루: 콘솔에만 찍고 진행
            Logger.getAnonymousLogger().log(Level.WARNING, "Log setup failed: " + e.getMessage(), e);
        }
    }

    /** 런타임에 로그 레벨 변경 (콘솔/파일 모두), save=true면 Preferences 저장 */
    public static void setLevel(Level level, boolean save) {
        if (level == null) level = Level.INFO;
        Logger root = Logger.getLogger("");
        root.setLevel(level);
        for (Handler h : root.getHandlers()) {
            h.setLevel(level);
        }
        if (save) {
            Preferences.userRoot().node(PREF_NODE).put(PREF_KEY_LEVEL, level.getName());
        }
        Logger.getLogger(LogSetup.class.getName()).log(level, "Log level switched to " + level.getName());
    }

    /** UI 초기 표시/복원용 */
    public static Level getSavedLevel() {
        String saved = Preferences.userRoot().node(PREF_NODE)
                .get(PREF_KEY_LEVEL, System.getProperty("wk.log.level", "INFO").toUpperCase(Locale.ROOT));
        return toLevel(saved);
    }

    /** 문자열을 Level로(실패 시 INFO) */
    public static Level levelOf(String name) { return toLevel(name); }

    /* ----------------- 내부 유틸 ----------------- */

    private static Level resolveInitialLevel() {
        // 1) Preferences 저장 값
        String pref = Preferences.userRoot().node(PREF_NODE).get(PREF_KEY_LEVEL, null);
        if (pref != null) return toLevel(pref);
        // 2) 시스템 프로퍼티
        String sys = System.getProperty("wk.log.level", "INFO");
        return toLevel(sys);
    }

    private static int parseInt(String s, int def) {
        try { return (s == null || s.isBlank()) ? def : Integer.parseInt(s.trim()); }
        catch (Exception ignored) { return def; }
    }

    private static Level toLevel(String s) {
        try { return Level.parse(String.valueOf(s).trim().toUpperCase(Locale.ROOT)); }
        catch (Exception e) { return Level.INFO; }
    }

    /** 한 줄 포맷 + 스레드명 + 예외 스택 */
    private static final class LineFormatter extends Formatter {
        @Override public String format(LogRecord r) {
            String msg = formatMessage(r);
            String base = String.format(Locale.ROOT,
                    "%1$tF %1$tT.%1$tL [%2$s] (%3$s) %4$s - %5$s%n",
                    r.getMillis(), r.getLevel().getName(),
                    Thread.currentThread().getName(),
                    r.getLoggerName(), msg);

            Throwable t = r.getThrown();
            if (t == null) return base;

            StringWriter sw = new StringWriter(256);
            t.printStackTrace(new PrintWriter(sw));
            return base + sw + System.lineSeparator();
        }
    }
}
