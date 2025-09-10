package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public final class HttpRobotsFetcher implements RobotsFetcher {
    private final HttpClient client;
    private final String userAgent;

    public HttpRobotsFetcher(HttpClient client) {
        this(client, "WebKillerAI");
    }
    public HttpRobotsFetcher(HttpClient client, String userAgent) {
        this.client = client;
        this.userAgent = (userAgent == null || userAgent.isBlank()) ? "WebKillerAI" : userAgent;
    }

    @Override
    public Response fetch(URI robotsTxtUri) {
        try {
            HttpRequest req = HttpRequest.newBuilder(robotsTxtUri)
                    .GET()
                    .header("User-Agent", userAgent)
                    .header("Accept", "text/plain,*/*;q=0.8")
                    .build();

            // HttpClient는 기본 Redirect.NEVER → repository가 직접 리다이렉트 판단
            HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            int code = res.statusCode();

            // 리다이렉트면 Location 헤더만 전달(본문은 무시)
            if (code == 301 || code == 302 || code == 307 || code == 308) {
                var locOpt = res.headers().firstValue("Location");
                URI next = locOpt.map(robotsTxtUri::resolve).orElse(robotsTxtUri);
                return new Response(code, "", next, null);
            }

            // 그 외 응답은 body 포함(2xx는 repository가 파싱, 4xx/5xx는 allow-all로 처리)
            String body = res.body() == null ? "" : res.body();
            return Response.ok(code, body, robotsTxtUri);

        } catch (Exception e) {
            return Response.fail(e.toString(), robotsTxtUri);
        }
    }
}
