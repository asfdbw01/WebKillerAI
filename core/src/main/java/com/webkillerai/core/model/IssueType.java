package com.webkillerai.core.model;

/** 탐지 이슈 분류 (MVP 시그니처 기반 + v0.4 SAFE_PLUS 최소 추가) */
public enum IssueType {
    // ===== MVP (현행) =====
    XSS_PATTERN,
    SQLI_PATTERN,
    OPEN_REDIRECT_PATTERN,
    DIRECTORY_LISTING,
    MISSING_SECURITY_HEADER,
    WEAK_CSP,
    COOKIE_HTTPONLY_MISSING,
    COOKIE_SECURE_MISSING,
    SERVER_ERROR_5XX,
    OTHER,

    // ===== v0.4 SAFE_PLUS 추가 =====
    XSS_REFLECTED,
    CORS_MISCONFIG,
    PATH_TRAVERSAL,
    SSTI,
    MIXED_CONTENT,

    // ===== Anomaly (LOW/INFO) =====
    ANOMALY_SIZE_DELTA,
    ANOMALY_CONTENT_TYPE_MISMATCH,
    ANOMALY_STACKTRACE_TOKEN
}
