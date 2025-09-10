package com.webkillerai.core.crawler.robots;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.Authenticator;              // ✅ 추가
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import static org.junit.jupiter.api.Assertions.*;

class RobotsCachePolicyTest {

    @Test
    void fetchAndCache_policy_allowsAndBlocks_asExpected() {
        String robotsTxt = """
                User-agent: WebKillerAI
                Disallow: /seed
                Disallow: /download/%2Fraw
                """;

        CountingFakeHttpClient fake = new CountingFakeHttpClient(Map.of(
                "https://example.com/robots.txt", new FakeResp(200, robotsTxt)
        ));

        RobotsCache cache = new RobotsCache(fake);

        URI seed = URI.create("https://example.com/seed");
        var polSeed = cache.policyFor(seed);
        assertFalse(polSeed.allow(seed));

        URI a = URI.create("https://example.com/download/%2Fraw");
        URI b = URI.create("https://example.com/download//raw");
        var pol = cache.policyFor(a);
        assertFalse(pol.allow(a));
        assertTrue(pol.allow(b));

        assertEquals(1, fake.count("https://example.com/robots.txt"));
    }

    @Test
    void failureFallsBack_toAllowAll() {
        CountingFakeHttpClient fake = new CountingFakeHttpClient(Map.of(
                "https://no-robots.com/robots.txt", new FakeResp(404, "not found")
        ));
        RobotsCache cache = new RobotsCache(fake);

        URI u = URI.create("https://no-robots.com/anything");
        assertTrue(cache.policyFor(u).allow(u));
        assertEquals(1, fake.count("https://no-robots.com/robots.txt"));
    }

    // ------------------ Fakes ------------------

    static final class CountingFakeHttpClient extends HttpClient {
        private final Map<String, FakeResp> table;
        private final Map<String, AtomicInteger> hits = new HashMap<>();

        CountingFakeHttpClient(Map<String, FakeResp> table) {
            this.table = table;
        }

        int count(String url) {
            return hits.getOrDefault(url, new AtomicInteger()).get();
        }

        @Override public Optional<CookieHandler> cookieHandler() { return Optional.empty(); }
        @Override public Optional<Duration> connectTimeout() { return Optional.of(Duration.ofSeconds(5)); }
        @Override public Redirect followRedirects() { return Redirect.NEVER; }
        @Override public Optional<ProxySelector> proxy() { return Optional.empty(); }
        @Override public SSLContext sslContext() { return null; }
        @Override public SSLParameters sslParameters() { return null; }
        @Override public Optional<Authenticator> authenticator() { return Optional.empty(); }          // ✅ 타입 고침
        @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }          // ✅ 타입 고침
        @Override public Optional<Executor> executor() { return Optional.empty(); }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
                throws IOException, InterruptedException {
            String url = request.uri().toString();
            hits.computeIfAbsent(url, k -> new AtomicInteger()).incrementAndGet();
            FakeResp resp = table.getOrDefault(url, new FakeResp(404, ""));
            @SuppressWarnings("unchecked")
            HttpResponse<T> r = (HttpResponse<T>) new FakeHttpResponse<>(request, resp.status, resp.body);
            return r;
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler, HttpResponse.PushPromiseHandler<T> pph) {
            throw new UnsupportedOperationException();
        }
    }

    static final class FakeResp {
        final int status; final String body;
        FakeResp(int status, String body) { this.status = status; this.body = body; }
    }

    static final class FakeHttpResponse<T> implements HttpResponse<T> {
        private final HttpRequest req;
        private final int status;
        private final T body;

        FakeHttpResponse(HttpRequest req, int status, T body) {
            this.req = req; this.status = status; this.body = body;
        }

        @Override public int statusCode() { return status; }
        @Override public HttpRequest request() { return req; }
        @Override public Optional<HttpResponse<T>> previousResponse() { return Optional.empty(); }
        @Override public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (a,b)->true); }
        @Override public T body() { return body; }
        @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
        @Override public URI uri() { return req.uri(); }
        @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }          // ✅ 타입 고침
    }
}
