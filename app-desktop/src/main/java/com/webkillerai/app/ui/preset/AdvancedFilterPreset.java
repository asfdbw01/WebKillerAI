package com.webkillerai.app.ui.preset;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.List;

/** AdvancedFilterBar 프리셋 파일 포맷 (v=1) */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AdvancedFilterPreset {
    public String v = "1";          // 스키마 버전
    public String name;             // 표시용 이름(옵션)
    public String logic;            // "AND" | "OR"
    public List<String> types;      // null/빈 = 무시
    public List<String> severities; // null/빈 = 무시
    public String urlContains;      // null 허용
    public String evidenceContains; // null 허용
    public String riskExpr;         // null/blank 허용
    public Instant dateFrom;        // null 허용 (inclusive)
    public Instant dateTo;          // null 허용 (exclusive)
}
