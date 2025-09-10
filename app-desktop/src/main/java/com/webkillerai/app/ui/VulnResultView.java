package com.webkillerai.app.ui;

import com.webkillerai.core.model.VulnResult;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

import java.net.URI;
import java.net.URL;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Objects;

public final class VulnResultView {
    private static final int EVIDENCE_MAX = 140;
    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final StringProperty url = new SimpleStringProperty();
    private final StringProperty type = new SimpleStringProperty();
    private final StringProperty severity = new SimpleStringProperty();
    private final StringProperty evidence = new SimpleStringProperty();
    private final StringProperty detectedAt = new SimpleStringProperty();

    public static VulnResultView from(VulnResult v) {
        VulnResultView vm = new VulnResultView();
        vm.setUrl(safeUrlString(v.getUrl()));
        vm.setType(v.getIssueType() != null ? v.getIssueType().name() : "");
        vm.setSeverity(v.getSeverity() != null ? v.getSeverity().name() : "");
        vm.setEvidence(trim(v.getEvidence(), EVIDENCE_MAX));
        vm.setDetectedAt(formatTs(v.getDetectedAt()));
        return vm;
    }

    private static String safeUrlString(Object url) {
        if (url == null) return "";
        if (url instanceof String s) return s;
        if (url instanceof URI u) return u.toString();
        if (url instanceof URL u) return u.toString();
        return String.valueOf(url);
    }

    private static String trim(String s, int max) {
        if (s == null) return "";
        if (max <= 0) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static String formatTs(Object ts) {
        if (ts == null) return "";
        if (ts instanceof Instant i) return TS_FMT.format(i);
        if (ts instanceof TemporalAccessor ta) return TS_FMT.format(ta);
        if (ts instanceof Number n) {
            long v = n.longValue();
            // 자주 헷갈리는 epoch 단위 처리(자릿수로 대략 구분)
            Instant i = (v > 3_000_000_000L) ? Instant.ofEpochMilli(v) : Instant.ofEpochSecond(v);
            return TS_FMT.format(i);
        }
        // 문자열 등은 그대로
        return Objects.toString(ts, "");
    }

    public StringProperty urlProperty() { return url; }
    public StringProperty typeProperty() { return type; }
    public StringProperty severityProperty() { return severity; }
    public StringProperty evidenceProperty() { return evidence; }
    public StringProperty detectedAtProperty() { return detectedAt; }

    public void setUrl(String v) { url.set(v); }
    public void setType(String v) { type.set(v); }
    public void setSeverity(String v) { severity.set(v); }
    public void setEvidence(String v) { evidence.set(v); }
    public void setDetectedAt(String v) { detectedAt.set(v); }

    // (선택) getter
    public String getUrl() { return url.get(); }
    public String getType() { return type.get(); }
    public String getSeverity() { return severity.get(); }
    public String getEvidence() { return evidence.get(); }
    public String getDetectedAt() { return detectedAt.get(); }
}
