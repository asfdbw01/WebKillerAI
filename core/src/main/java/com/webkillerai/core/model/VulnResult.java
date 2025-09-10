package com.webkillerai.core.model;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;

/** 단일 취약점(징후) 결과 */
public final class VulnResult {
    private final URI url;
    private final IssueType issueType;
    private final Severity severity;
    private final String description;   // 사람이 읽을 수 있는 요약
    private final String evidence;      // (기존) 매칭된 패턴/헤더 등 - 하위호환 유지
    private final double confidence;    // 0.0~1.0
    private final Instant detectedAt;
    private final Integer riskScore;    // 0..100, nullable

    // === v0.4 추가 증거 필드 ===
    private final String requestLine;     // 예: "GET /path?x=1 HTTP/1.1"
    private final String evidenceSnippet; // 응답 스니펫(±80자)

    private VulnResult(Builder b) {
        this.url = b.url;
        this.issueType = b.issueType;
        this.severity = b.severity;
        this.description = b.description;
        this.evidence = b.evidence;
        this.confidence = b.confidence;
        this.detectedAt = (b.detectedAt == null ? Instant.now() : b.detectedAt);
        this.riskScore = b.riskScore;
        this.requestLine = b.requestLine;
        this.evidenceSnippet = b.evidenceSnippet;
    }

    public URI getUrl() { return url; }
    public IssueType getIssueType() { return issueType; }
    public Severity getSeverity() { return severity; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public double getConfidence() { return confidence; }
    public Instant getDetectedAt() { return detectedAt; }
    public Integer getRiskScore() { return riskScore; }
    public String getRequestLine() { return requestLine; }
    public String getEvidenceSnippet() { return evidenceSnippet; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private URI url;
        private IssueType issueType;
        private Severity severity;
        private String description;
        private String evidence;
        private double confidence = 0.7;
        private Instant detectedAt;
        private Integer riskScore;        // nullable

        // v0.4 추가 필드
        private String requestLine;
        private String evidenceSnippet;

        public Builder url(URI url) { this.url = url; return this; }
        public Builder issueType(IssueType issueType) { this.issueType = issueType; return this; }
        public Builder severity(Severity severity) { this.severity = severity; return this; }
        public Builder description(String description) { this.description = description; return this; }
        public Builder evidence(String evidence) { this.evidence = evidence; return this; }
        public Builder confidence(double confidence) { this.confidence = confidence; return this; }
        public Builder detectedAt(Instant detectedAt) { this.detectedAt = detectedAt; return this; }
        public Builder riskScore(Integer riskScore) { this.riskScore = riskScore; return this; }

        // v0.4 추가 세터
        public Builder requestLine(String requestLine) { this.requestLine = requestLine; return this; }
        public Builder evidenceSnippet(String evidenceSnippet) { this.evidenceSnippet = evidenceSnippet; return this; }

        public VulnResult build() {
            Objects.requireNonNull(url, "url");
            Objects.requireNonNull(issueType, "issueType");
            Objects.requireNonNull(severity, "severity");
            return new VulnResult(this);
        }
    }
}
