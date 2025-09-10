package com.webkillerai.core.scanner.dedupe;

import java.net.URI;

/**
 * 중복 억제용 키: (url, paramKey, issueType, signal)
 * signal은 탐지 내부 추가 구분자(옵션) — null이면 ""로 치환
 */
public record DedupeKey(URI url, String paramKey, String issueType, String signal) {
    public static DedupeKey of(URI url, String paramKey, String issueType, String signal) {
        return new DedupeKey(url, paramKey == null ? "" : paramKey,
                                  issueType, signal == null ? "" : signal);
    }
}
