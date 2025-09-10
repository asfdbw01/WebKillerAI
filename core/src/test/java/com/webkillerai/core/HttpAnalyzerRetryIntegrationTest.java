package com.webkillerai.core;

import com.webkillerai.core.http.HttpAnalyzer;
import com.webkillerai.core.http.RetryPolicy;
import com.webkillerai.core.model.HttpResponseData;
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.util.Sleeper;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

class HttpAnalyzerRetryIntegrationTest {

    /** 테스트용 Sleeper: sleep(Duration) 호출 기록 */
    static class TestSleeper implements Sleeper {
        final List<Duration> sleeps = new ArrayList<>();
        @Override public void sleep(Duration d) { sleeps.add(d); }
    }

    /** 테스트용 HttpResponse<String> */
    static class Resp implements HttpResponse<String> {
        final int code; final Map<String,List<String>> headers; final String body;
        Resp(int code, Map<String,List<String>> headers, String body) {
            this.code = code; this.headers = headers; this.body = body;
        }
        @Override public int statusCode() { return code; }
        @Override public HttpRequest request() { return null; }
        @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
        @Override public HttpHeaders headers() { return HttpHeaders.of(headers, (a,b)->true); }
        @Override public String body() { return body; }
        @Override public Optional<javax.net.ssl.SSLSession> sslSession() { return Optional.empty(); }
        @Override public URI uri() { return URI.create("https://example.com"); }
        @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
    }

    @Test
    void retryAfter_is_honored_on_429_and_succeeds_on_second_attempt() throws Exception {
        // 1) 최소 설정
        ScanConfig cfg = new ScanConfig();
        cfg.setTimeoutMs(2000);
        cfg.setFollowRedirects(false);

        // 2) 1회차 429 + Retry-After: 1 → 2회차 200
        AtomicInteger calls = new AtomicInteger(0);
        HttpAnalyzer.HttpSender sender = req -> {
            int n = calls.incrementAndGet();
            if (n == 1) {
                return new Resp(429, Map.of("Retry-After", List.of("1")), "slow down");
            }
            return new Resp(200, Map.of(), "ok");
        };

        // 3) Analyzer (훅 주입)
        HttpAnalyzer analyzer = new HttpAnalyzer(cfg, sender);

        // 4) 정책: 테스트 내 구현(최대 3회, 429/5xx/(-1)에서만 재시도, 지수백오프 250ms 기준)
        RetryPolicy policy = new RetryPolicy() {
            @Override public boolean shouldRetry(int status, int attempt) {
                return (status == 429 || status == -1 || status >= 500) && attempt < 3;
            }
            @Override public Duration nextDelay(int attempt) {
                // 1→250ms, 2→500ms … (지터 미적용; 테스트 목적상 OK)
                long base = 250L * (1L << (attempt - 1));
                return Duration.ofMillis(base);
            }
            @Override public int maxAttempts() { return 3; }
        };

        TestSleeper sleeper = new TestSleeper();

        // 5) 실행
        HttpResponseData data = analyzer.analyzeWithRetry(URI.create("https://example.com"), policy, sleeper);

        // 6) 검증
        Assertions.assertThat(data.getStatusCode()).isEqualTo(200);
        Assertions.assertThat(calls.get()).isEqualTo(2);

        // 첫 sleep은 Retry-After=1초 우선(±10% 허용)
        Assertions.assertThat(sleeper.sleeps).isNotEmpty();
        long firstMs = sleeper.sleeps.get(0).toMillis();
        Assertions.assertThat(firstMs).isBetween(900L, 1100L);
    }
}
