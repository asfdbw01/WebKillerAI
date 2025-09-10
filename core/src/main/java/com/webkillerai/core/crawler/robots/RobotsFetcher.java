package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.util.Optional;

public interface RobotsFetcher {
    final class Response {
        public final int status;                // HTTP status (0 이면 네트워크 오류 같은 비정상)
        public final String body;               // text/robots
        public final URI finalUri;              // 리다이렉트 후 최종 URI (없으면 요청 URI)
        public final Optional<String> error;    // 오류 메시지

        public Response(int status, String body, URI finalUri, String error) {
            this.status = status;
            this.body = body;
            this.finalUri = finalUri;
            this.error = Optional.ofNullable(error);
        }
        public static Response ok(int status, String body, URI finalUri) {
            return new Response(status, body, finalUri, null);
        }
        public static Response fail(String msg, URI finalUri) {
            return new Response(0, "", finalUri, msg);
        }
    }

    /** robots.txt를 받아온다. 리다이렉트는 호출자가 처리한다. */
    Response fetch(URI robotsTxtUri);
}
