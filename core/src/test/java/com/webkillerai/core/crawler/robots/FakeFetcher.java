package com.webkillerai.core.crawler.robots;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

final class FakeFetcher implements RobotsFetcher {
    static final class Stub {
        final int status; final String body; final URI finalUri; final String err;
        Stub(int status, String body, URI finalUri, String err) {
            this.status = status; this.body = body; this.finalUri = finalUri; this.err = err;
        }
    }
    private final Map<String, Stub> byUri = new LinkedHashMap<>();

    FakeFetcher stub(URI uri, int status, String body) {
        byUri.put(uri.toString(), new Stub(status, body, uri, null));
        return this;
    }
    FakeFetcher redirect(URI from, URI to, int status) {
        byUri.put(from.toString(), new Stub(status, "", to, null));
        return this;
    }
    FakeFetcher fail(URI uri, String err) {
        byUri.put(uri.toString(), new Stub(0, "", uri, err));
        return this;
    }

    @Override public Response fetch(URI robotsTxtUri) {
        Stub s = byUri.get(robotsTxtUri.toString());
        if (s == null) return Response.fail("no stub", robotsTxtUri);
        if (s.status == 0) return Response.fail(s.err, robotsTxtUri);
        if (s.finalUri != null && (s.status == 301 || s.status == 302 || s.status == 307 || s.status == 308)) {
            return new Response(s.status, s.body, s.finalUri, null);
        }
        return Response.ok(s.status, s.body, robotsTxtUri);
    }
}
