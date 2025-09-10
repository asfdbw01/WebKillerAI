package com.webkillerai.core.scanner.detectors;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MixedContentDetectorTest {

    @Test
    void finds_http_subresources_in_https_document() {
        String html = """
          <html><head>
            <link rel="stylesheet" href="http://cdn.example.com/a.css">
            <script src="http://cdn.example.com/a.js"></script>
          </head>
          <body>
            <img src="http://img.example.com/p.png">
            <iframe src="http://x.example.com/frame.html"></iframe>
          </body></html>
        """;
        List<String> hits = MixedContentDetector.findMixedUrls(html, URI.create("https://site.example/page"));
        assertFalse(hits.isEmpty());
        assertTrue(hits.get(0).startsWith("<"));
        assertTrue(hits.stream().anyMatch(s -> s.contains("http://")));
    }
}
