package com.webkillerai.core.model;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** HTTP 응답 캡처(본문은 텍스트 기준, 필요시 바이트 확장 가능) */
public final class HttpResponseData {
    private final URI url;
    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final String body;
    private final String contentType;
    private final long responseTimeMs;

    private HttpResponseData(Builder b) {
        this.url = b.url;
        this.statusCode = b.statusCode;
        this.headers = (b.headers == null) ? Map.of() : Collections.unmodifiableMap(b.headers);
        this.body = (b.body == null) ? "" : b.body;
        this.contentType = b.contentType;
        this.responseTimeMs = b.responseTimeMs;
    }

    // ----- 기존 게터 -----
    public URI getUrl() { return url; }
    public int getStatusCode() { return statusCode; }
    public Map<String, List<String>> getHeaders() { return headers; }
    public String getBody() { return body; }
    public String getContentType() { return contentType; }
    public long getResponseTimeMs() { return responseTimeMs; }

    // ----- [추가] 공용 헬퍼: 디텍터/리포터용 표준 접근 -----

    /** getUrl()의 별칭. 디텍터에서 일관 API로 사용. */
    public URI getUri() {
        return url;
    }

    /** 첫 번째 헤더 값(대소문자 무시). 없으면 null. */
    public String header(String name) {
        if (name == null || headers == null) return null;
        for (var e : headers.entrySet()) {
            final String k = e.getKey();
            if (k != null && k.equalsIgnoreCase(name)) {
                final List<String> vs = e.getValue();
                return (vs == null || vs.isEmpty()) ? null : vs.get(0);
            }
        }
        return null;
    }

    /** 모든 헤더 값(대소문자 무시). 없으면 빈 리스트. */
    public List<String> headers(String name) {
        if (name == null || headers == null) return List.of();
        for (var e : headers.entrySet()) {
            final String k = e.getKey();
            if (k != null && k.equalsIgnoreCase(name)) {
                return (e.getValue() != null) ? e.getValue() : List.of();
            }
        }
        return List.of();
    }

    // ----- 빌더 -----
    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private URI url;
        private int statusCode;
        private Map<String, List<String>> headers;
        private String body;
        private String contentType;
        private long responseTimeMs;

        public Builder url(URI url) { this.url = url; return this; }
        public Builder statusCode(int statusCode) { this.statusCode = statusCode; return this; }
        public Builder headers(Map<String, List<String>> headers) { this.headers = headers; return this; }
        public Builder body(String body) { this.body = body; return this; }
        public Builder contentType(String contentType) { this.contentType = contentType; return this; }
        public Builder responseTimeMs(long responseTimeMs) { this.responseTimeMs = responseTimeMs; return this; }

        public HttpResponseData build() {
            Objects.requireNonNull(url, "url");
            return new HttpResponseData(this);
        }
    }
}
