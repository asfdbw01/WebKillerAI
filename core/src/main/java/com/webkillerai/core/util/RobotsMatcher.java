package com.webkillerai.core.util;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

public final class RobotsMatcher {

    private final List<Rule> rules; // Allow/Disallow only (from User-agent: * groups)

    private RobotsMatcher(List<Rule> rules) {
        this.rules = rules;
    }

    /** Parse robots.txt (null/empty safe). Only User-agent: * rules are collected. */
    public static RobotsMatcher parse(String robotsTxt) {
        if (robotsTxt == null) return new RobotsMatcher(List.of());

        List<Rule> out = new ArrayList<>();
        boolean inAny = false;          // inside some group
        boolean active = false;         // inside a group that applies to "*"
        for (String raw : robotsTxt.split("\\r?\\n")) {
            String line = raw.strip();
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash).strip();
            if (line.isEmpty()) continue;

            int colon = line.indexOf(':');
            if (colon <= 0) continue;

            String key = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String val = line.substring(colon + 1).trim();

            switch (key) {
                case "user-agent":
                    String ua = val.toLowerCase(Locale.ROOT);
                    // new group begins when we see user-agent; multiple UAs may follow
                    if (!inAny) { inAny = true; active = false; }
                    // if any UA in this group is "*", mark active
                    if (ua.equals("*")) active = true;
                    break;
                case "allow":
                case "disallow":
                    if (!inAny) break;             // ignore rules before any UA
                    if (!active) break;            // only collect from UA:* groups
                    out.add(new Rule(key.equals("allow"), val));
                    break;
                default:
                    // ignore others for MVP (crawl-delay, sitemap, etc.)
            }
        }
        return new RobotsMatcher(out);
    }

    /** Returns true if the URL is allowed to crawl under parsed rules. */
    public boolean isAllowed(URI url) {
        // Build target: path + (query if present)
        String path = normalize(url);
        // Find best (longest) matching rule; tie -> Allow wins
        Rule best = null;
        for (Rule r : rules) {
            if (r.matches(path)) {
                if (best == null || r.matchLen > best.matchLen ||
                   (r.matchLen == best.matchLen && r.allow && !best.allow)) {
                    best = r;
                }
            }
        }
        // Default allow if no rule matched
        return best == null ? true : best.allow;
    }

    private static String normalize(URI u) {
        String p = (u.getRawPath() == null || u.getRawPath().isEmpty()) ? "/" : u.getRawPath();
        String q = u.getRawQuery();
        if (q != null && !q.isEmpty()) p = p + "?" + q;
        return p;
    }

    // ---- Rule ----

    private static final class Rule {
        final boolean allow;
        final Pattern pattern;
        final String raw;
        int matchLen; // last match length for current check

        Rule(boolean allow, String patternText) {
            this.allow = allow;
            this.raw = (patternText == null) ? "" : patternText.trim();
            this.pattern = compile(raw);
        }

        boolean matches(String path) {
            var m = pattern.matcher(path);
            if (!m.find()) return false;
            // match length = end-start (prefer longest)
            matchLen = m.end() - m.start();
            return true;
        }

        private static Pattern compile(String s) {
            // Empty Disallow means allow-all per REP; but we only create Rule when key present.
            if (s.isEmpty()) return Pattern.compile("(?!)"); // never matches
            // Supports * and $ ; everything else literal; anchored with find() semantics
            StringBuilder rx = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '*') rx.append(".*");
                else if (c == '$') rx.append('$');
                else {
                    if ("\\.[]{}()+-^$|?".indexOf(c) >= 0) rx.append('\\');
                    rx.append(c);
                }
            }
            // Case-sensitive by default (web servers are often case-sensitive). Adjust if needed.
            return Pattern.compile(rx.toString());
        }
    }
}
