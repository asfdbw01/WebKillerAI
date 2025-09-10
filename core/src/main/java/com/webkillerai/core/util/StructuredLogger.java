package com.webkillerai.core.util;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class StructuredLogger {
    private final Logger jul;
    private final String comp;

    private StructuredLogger(Class<?> cls) {
        this.jul = Logger.getLogger(cls.getName());
        this.comp = cls.getSimpleName();
    }
    public static StructuredLogger get(Class<?> cls) { return new StructuredLogger(cls); }

    public void debug(String event, Object... kvs) { log(Level.FINE, event, null, kvs); }
    public void info (String event, Object... kvs) { log(Level.INFO, event, null, kvs); }
    public void warn (String event, Object... kvs) { log(Level.WARNING, event, null, kvs); }
    public void error(String event, Throwable t, Object... kvs) { log(Level.SEVERE, event, t, kvs); }

    private void log(Level lvl, String event, Throwable t, Object... kvs) {
        if (!jul.isLoggable(lvl)) return;
        StringBuilder sb = new StringBuilder(128);
        sb.append('{')
          .append(JsonUtil.kv("ts", Instant.now().toString())).append(',')
          .append(JsonUtil.kv("lvl", lvl.getName())).append(',')
          .append(JsonUtil.kv("comp", comp)).append(',')
          .append(JsonUtil.kv("thread", Thread.currentThread().getName())).append(',')
          .append(JsonUtil.kv("event", event));

        // kvs: "key", value, ...
        if (kvs != null && kvs.length > 0) {
            for (int i = 0; i < kvs.length - 1; i += 2) {
                Object k = kvs[i];
                Object v = kvs[i + 1];
                sb.append(',').append(JsonUtil.kv(String.valueOf(k), v));
            }
            if (kvs.length % 2 == 1) { // 홀수 방지용
                sb.append(',').append(JsonUtil.kv("_kv_mismatch", true));
            }
        }
        if (t != null) {
            sb.append(',').append(JsonUtil.kv("error", t.getClass().getSimpleName()))
              .append(',').append(JsonUtil.kv("message", String.valueOf(t.getMessage())));
        }
        sb.append('}');
        String line = sb.toString();
        if (t == null) jul.log(lvl, line); else jul.log(lvl, line, t);
    }
}
