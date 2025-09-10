package com.webkillerai.core.crawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

/** 기본 JSoup 기반 링크 추출기: a[href] → abs:href 수집 */
public class JsoupLinkExtractor implements LinkExtractor {
    private final int timeoutMs;
    private final boolean followRedirects;

    public JsoupLinkExtractor(long timeoutMs, boolean followRedirects) {
        // jsoup timeout은 int 필요 → 안전 캐스팅
        long clamped = Math.max(0, Math.min(Integer.MAX_VALUE, timeoutMs));
        this.timeoutMs = (int) clamped;
        this.followRedirects = followRedirects;
    }

    @Override
    public Set<URI> extract(URI base) throws Exception {
        Set<URI> out = new HashSet<>();
        if (base == null) return out;

        Document doc = Jsoup.connect(base.toString())
                .userAgent("WebKillerAI/0.1 (+crawler)")
                .timeout(timeoutMs)
                .followRedirects(followRedirects)
                .get();

        for (Element a : doc.select("a[href]")) {
            String abs = a.attr("abs:href");
            if (abs == null || abs.isBlank()) continue;
            try {
                URI u = URI.create(abs.trim());
                String s = u.getScheme();
                if (s == null) continue;
                if (!s.equalsIgnoreCase("http") && !s.equalsIgnoreCase("https")) continue;
                out.add(u);
            } catch (IllegalArgumentException ignore) {
                // 잘못된 URL은 무시
            }
        }
        return out;
    }
}
