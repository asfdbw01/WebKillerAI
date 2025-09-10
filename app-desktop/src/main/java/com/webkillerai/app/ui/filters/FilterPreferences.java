package com.webkillerai.app.ui.filters;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Severity;

import java.time.LocalDate;
import java.util.EnumSet;
import java.util.prefs.Preferences;

public final class FilterPreferences {
    private FilterPreferences(){}

    private static final String NS = "ui.filter.";
    private static final String K_TYPE = NS + "type";
    private static final String K_SEV = NS + "severity";
    private static final String K_MODE = NS + "mode";
    private static final String K_URL = NS + "url.contains";
    private static final String K_EVI = NS + "evi.contains";
    private static final String K_RISK = NS + "risk.expr";
    private static final String K_FROM = NS + "date.from";
    private static final String K_TO = NS + "date.to";
    private static final String K_SORT_COL = NS + "sort.column";
    private static final String K_SORT_DIR = NS + "sort.direction";
    private static final String K_RESTORE = NS + "restore.onCancel";

    public static FilterState load(Preferences p) {
        if (p == null) p = Preferences.userRoot().node("/com/webkillerai/app");
        var def = FilterState.defaults();

        var types = parseIssueTypes(p.get(K_TYPE, ""));
        var sevs  = parseSeverities(p.get(K_SEV, ""));
        var mode  = parseEnum(p.get(K_MODE, def.mode.name()), FilterState.Mode.class, FilterState.Mode.OR);
        var url   = p.get(K_URL, "");
        var evi   = p.get(K_EVI, "");
        var risk  = p.get(K_RISK, "");
        var from  = parseDate(p.get(K_FROM, ""));
        var to    = parseDate(p.get(K_TO, ""));
        var sCol  = parseEnum(p.get(K_SORT_COL, def.sortColumn.name()), FilterState.SortColumn.class, FilterState.SortColumn.DETECTED_AT);
        var sDir  = parseEnum(p.get(K_SORT_DIR, def.sortDir.name()), FilterState.SortDir.class, FilterState.SortDir.DESC);
        var restore = Boolean.parseBoolean(p.get(K_RESTORE, "true"));

        return FilterState.of(types, sevs, mode, url, evi, risk, from, to, sCol, sDir, restore);
    }

    public static void save(Preferences p, FilterState s) {
        if (p == null) p = Preferences.userRoot().node("/com/webkillerai/app");
        if (s == null) s = FilterState.defaults();
        p.put(K_TYPE, joinEnumSet(s.types));
        p.put(K_SEV, joinEnumSet(s.severities));
        p.put(K_MODE, s.mode.name());
        p.put(K_URL, nonNull(s.urlContains));
        p.put(K_EVI, nonNull(s.evidenceContains));
        p.put(K_RISK, nonNull(s.riskExpr));
        p.put(K_FROM, s.dateFrom == null ? "" : s.dateFrom.toString());
        p.put(K_TO, s.dateTo == null ? "" : s.dateTo.toString());
        p.put(K_SORT_COL, s.sortColumn.name());
        p.put(K_SORT_DIR, s.sortDir.name());
        p.put(K_RESTORE, Boolean.toString(s.restoreOnCancel));
    }

    public static void reset(Preferences p) {
        save(p, FilterState.defaults());
    }

    // ---- helpers ----
    private static String nonNull(String s){ return s == null ? "" : s; }

    private static EnumSet<IssueType> parseIssueTypes(String csv) {
        var set = EnumSet.noneOf(IssueType.class);
        for (String t : csv.split(",")) {
            t = t.trim();
            if (t.isEmpty()) continue;
            try { set.add(IssueType.valueOf(t)); } catch (Exception ignore) {}
        }
        return set;
    }
    private static EnumSet<Severity> parseSeverities(String csv) {
        var set = EnumSet.noneOf(Severity.class);
        for (String t : csv.split(",")) {
            t = t.trim();
            if (t.isEmpty()) continue;
            try { set.add(Severity.valueOf(t)); } catch (Exception ignore) {}
        }
        return set;
    }
    private static <E extends Enum<E>> E parseEnum(String s, Class<E> c, E def) {
        try { return Enum.valueOf(c, s); } catch (Exception e) { return def; }
    }
    private static LocalDate parseDate(String s) {
        try { return (s == null || s.isBlank()) ? null : LocalDate.parse(s); }
        catch (Exception e) { return null; }
    }
    private static String joinEnumSet(EnumSet<?> set) {
        if (set == null || set.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (var e : set) {
            if (sb.length() > 0) sb.append(',');
            sb.append(e.name());
        }
        return sb.toString();
    }
}
