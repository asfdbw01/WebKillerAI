package com.webkillerai.app.ui.filters;

import com.webkillerai.core.model.IssueType;
import com.webkillerai.core.model.Severity;

import java.time.LocalDate;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

public final class FilterState {

    public enum Mode { AND, OR }
    public enum SortColumn { URL, TYPE, SEVERITY, RISK, DETECTED_AT }
    public enum SortDir { ASC, DESC }

    public final EnumSet<IssueType> types;
    public final EnumSet<Severity> severities;
    public final Mode mode;
    public final String urlContains;
    public final String evidenceContains;
    public final String riskExpr;          // 예: ">=50", "25-80", "42"
    public final LocalDate dateFrom;       // nullable
    public final LocalDate dateTo;         // nullable
    public final SortColumn sortColumn;
    public final SortDir sortDir;
    public final boolean restoreOnCancel;

    private FilterState(EnumSet<IssueType> types, EnumSet<Severity> severities, Mode mode,
                        String urlContains, String evidenceContains, String riskExpr,
                        LocalDate dateFrom, LocalDate dateTo,
                        SortColumn sortColumn, SortDir sortDir, boolean restoreOnCancel) {
        this.types = types == null ? EnumSet.noneOf(IssueType.class) : EnumSet.copyOf(types);
        this.severities = severities == null ? EnumSet.noneOf(Severity.class) : EnumSet.copyOf(severities);
        this.mode = mode == null ? Mode.OR : mode;
        this.urlContains = urlContains == null ? "" : urlContains;
        this.evidenceContains = evidenceContains == null ? "" : evidenceContains;
        this.riskExpr = riskExpr == null ? "" : riskExpr;
        this.dateFrom = dateFrom;
        this.dateTo = dateTo;
        this.sortColumn = sortColumn == null ? SortColumn.DETECTED_AT : sortColumn;
        this.sortDir = sortDir == null ? SortDir.DESC : sortDir;
        this.restoreOnCancel = restoreOnCancel;
    }

    public static FilterState defaults() {
        return new FilterState(
                EnumSet.noneOf(IssueType.class),
                EnumSet.noneOf(Severity.class),
                Mode.OR,
                "", "", "",
                null, null,
                SortColumn.DETECTED_AT, SortDir.DESC,
                true
        );
    }

    public static FilterState of(Set<IssueType> types, Set<Severity> severities, Mode mode,
                                 String urlContains, String evidenceContains, String riskExpr,
                                 LocalDate dateFrom, LocalDate dateTo,
                                 SortColumn sortColumn, SortDir sortDir, boolean restoreOnCancel) {
        return new FilterState(types == null ? EnumSet.noneOf(IssueType.class) : EnumSet.copyOf(types),
                severities == null ? EnumSet.noneOf(Severity.class) : EnumSet.copyOf(severities),
                mode, urlContains, evidenceContains, riskExpr, dateFrom, dateTo, sortColumn, sortDir, restoreOnCancel);
    }

    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FilterState that)) return false;
        return restoreOnCancel == that.restoreOnCancel &&
                Objects.equals(types, that.types) &&
                Objects.equals(severities, that.severities) &&
                mode == that.mode &&
                Objects.equals(urlContains, that.urlContains) &&
                Objects.equals(evidenceContains, that.evidenceContains) &&
                Objects.equals(riskExpr, that.riskExpr) &&
                Objects.equals(dateFrom, that.dateFrom) &&
                Objects.equals(dateTo, that.dateTo) &&
                sortColumn == that.sortColumn &&
                sortDir == that.sortDir;
    }
    @Override public int hashCode() {
        return Objects.hash(types, severities, mode, urlContains, evidenceContains, riskExpr,
                dateFrom, dateTo, sortColumn, sortDir, restoreOnCancel);
    }
}
