package com.webkillerai.core.http;

import com.webkillerai.core.api.IHttpAnalyzer;
import com.webkillerai.core.model.HttpResponseData;
import com.webkillerai.core.model.ScanConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** HTTP 분석 스텁: 실제 요청 전송 후 HttpResponseData로 매핑 */
public class HttpAnalyzer implements IHttpAnalyzer {

    /** ✅ 추가: 테스트/모킹용 송신 훅 */
    @FunctionalInterface
    public interface HttpSender {
        HttpResponse<String> send(HttpRequest req) throws Exception;
    }

    private final ScanConfig config;
    private final HttpClient client;   // 프로덕션 경로
    private final HttpSender sender;   // 테스트 경로(있으면 이걸 사용)

    public HttpAnalyzer(ScanConfig config) {
        this.config = Objects.requireNonNull(config, "config");
        this.client = HttpClient.newBuilder()
                .followRedirects(config.isFollowRedirects() ? HttpClient.Redirect.NORMAL : HttpClient.Redirect.NEVER)
                .connectTimeout(config.getTimeout())
                .build();
        this.sender = null; // 기본은 HttpClient 사용
    }

    /** ✅ 추가: 테스트용 생성자(송신 훅 주입) */
    public HttpAnalyzer(ScanConfig config, HttpSender testSender) {
        this.config = Objects.requireNonNull(config, "config");
        this.client = null; // 테스트에선 사용 안 함
        this.sender = Objects.requireNonNull(testSender, "testSender");
    }

    /** GET 요청을 보내고 결과를 HttpResponseData로 반환. (예외 시 status -1 반환) */
    public HttpResponseData analyze(URI url) {
        Objects.requireNonNull(url, "url");
        long start = System.nanoTime();
        try {
            Duration timeout = config.getTimeout();
            HttpRequest req = HttpRequest.newBuilder(url)
                    .timeout(timeout)
                    .GET()
                    .build();

            // ✅ 변경: sender가 있으면 sender로, 아니면 기존 HttpClient로 전송
            HttpResponse<String> resp = (sender != null)
                    ? sender.send(req)
                    : client.send(req, HttpResponse.BodyHandlers.ofString());

            long elapsedMs = (System.nanoTime() - start) / 1_000_000;

            HttpHeaders hh = resp.headers();
            Map<String, List<String>> headers = hh.map();
            String contentType = hh.firstValue("Content-Type").orElse(null);

            return HttpResponseData.builder()
                    .url(url)
                    .statusCode(resp.statusCode())
                    .headers(headers)
                    .body(resp.body() == null ? "" : resp.body())
                    .contentType(contentType)
                    .responseTimeMs(elapsedMs)
                    .build();
        } catch (Exception e) {
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            return HttpResponseData.builder()
                    .url(url)
                    .statusCode(-1)
                    .headers(Map.of())
                    .body("")
                    .contentType(null)
                    .responseTimeMs(elapsedMs)
                    .build();
        }
    }

    /** 재시도 포함 버전: 429/5xx/(-1)에서만 재시도, Retry-After 우선 */
    public HttpResponseData analyzeWithRetry(URI url,
                                             com.webkillerai.core.http.RetryPolicy policy,
                                             com.webkillerai.core.util.Sleeper sleeper) throws InterruptedException {
        int attempt = 1;
        while (true) {
            HttpResponseData data = analyze(url); // 기존 메서드 재사용(예외 시 -1로 반환)
            int status = data.getStatusCode();

            if (!policy.shouldRetry(status, attempt)) {
                return data;
            }
            // 다음 시도 전 대기(Retry-After 우선, 상한 30s)
            java.time.Duration delay = resolveRetryAfterOr(policy.nextDelay(attempt), data);
            sleeper.sleep(delay);

            attempt++;
            if (attempt > policy.maxAttempts()) {
                return data; // 마지막 시도 결과 반환
            }
        }
    }

    /** Retry-After 헤더를 존중하되 과도한 대기는 30초로 상한 */
    private java.time.Duration resolveRetryAfterOr(java.time.Duration fallback, HttpResponseData data) {
        try {
            var headers = data.getHeaders(); // Map<String, List<String>>
            if (headers == null) return fallback;
            var values = headers.get("Retry-After");
            if (values == null || values.isEmpty()) values = headers.get("retry-after");
            if (values == null || values.isEmpty()) return fallback;

            String v = values.get(0).trim();
            // seconds 형태
            try {
                long sec = Long.parseLong(v);
                return java.time.Duration.ofSeconds(Math.min(sec, 30));
            } catch (NumberFormatException ignore) { /* fallthrough */ }

            // HTTP-date 형태는 단순히 fallback 사용(간소화; 필요 시 RFC1123 파싱 추가)
            return fallback;
        } catch (Exception e) {
            return fallback;
        }
    }
}
