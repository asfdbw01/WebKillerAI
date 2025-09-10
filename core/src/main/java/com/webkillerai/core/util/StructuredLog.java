package com.webkillerai.core.util;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JSON 라인 기반 구조화 로거.
 * LogSetup(콘솔/파일 핸들러) 세팅 후 여기서 호출하면 JSON 문자열로 찍힘.
 */
public final class StructuredLog {
    private final Logger jul;
    private final String comp;

    private StructuredLog(Class<?> cls) {
        this.jul = Logger.getLogger(cls.getName());
        this.comp = cls.getSimpleName();
    }

    public static StructuredLog get(Class<?> cls) {
        return new StructuredLog(cls);
    }

    public void debug(String event, Object... kvs) { log(Level.FINE,   event, null, kvs); }
    public void info (String event, Object... kvs) { log(Level.INFO,   event, null, kvs); }
    public void warn (String event, Object... kvs) { log(Level.WARNING,event, null, kvs); }
    public void error(String event, Throwable t, Object... kvs) { log(Level.SEVERE, event, t, kvs); }

    private void log(Level lvl, String event, Throwable t, Object... kvs) {
        if (!jul.isLoggable(lvl)) return;
        String line = buildJson(lvl, event, t, kvs);
        if (t == null) jul.log(lvl, line); else jul.log(lvl, line, t);
    }

    private String buildJson(Level lvl, String event, Throwable t, Object... kvs) {
        StringBuilder sb = new StringBuilder(128);
        sb.append('{');
        kv(sb, "ts", Instant.now().toString());
        kv(sb, "lvl", lvl.getName());
        kv(sb, "comp", comp);
        kv(sb, "thread", Thread.currentThread().getName());
        kv(sb, "event", event);

        if (kvs != null && kvs.length > 0) {
            for (int i = 0; i + 1 < kvs.length; i += 2) {
                kv(sb, String.valueOf(kvs[i]), kvs[i + 1]);
            }
            if (kvs.length % 2 == 1) kv(sb, "_kv_mismatch", true);
        }
        if (t != null) {
            kv(sb, "error", t.getClass().getSimpleName());
            kv(sb, "message", t.getMessage());
        }
        // 마지막 콤마 제거
        if (sb.charAt(sb.length() - 1) == ',') sb.setLength(sb.length() - 1);
        sb.append('}');
        return sb.toString();
    }

    private static void kv(StringBuilder sb, String k, Object v) {
        sb.append('"').append(esc(k)).append('"').append(':');
        if (v == null) {
            sb.append("null");
        } else if (v instanceof Number || v instanceof Boolean) {
            sb.append(String.valueOf(v));
        } else {
            sb.append('"').append(esc(String.valueOf(v))).append('"');
        }
        sb.append(',');
    }

    private static String esc(String s) {
        StringBuilder r = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  r.append("\\\""); break;
                case '\\': r.append("\\\\"); break;
                case '\n': r.append("\\n");  break;
                case '\r': r.append("\\r");  break;
                case '\t': r.append("\\t");  break;
                default:
                    if (c < 0x20) r.append(String.format("\\u%04x", (int)c));
                    else r.append(c);
            }
        }
        return r.toString();
    }
}
