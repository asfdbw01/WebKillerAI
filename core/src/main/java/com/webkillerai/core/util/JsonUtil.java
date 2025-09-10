package com.webkillerai.core.util;

final class JsonUtil {
    private JsonUtil() {}
    static String esc(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int)c));
                    else sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }
    static String kv(String k, Object v) {
        return esc(k) + ":" + (v instanceof Number || v instanceof Boolean ? String.valueOf(v) : esc(String.valueOf(v)));
    }
}
