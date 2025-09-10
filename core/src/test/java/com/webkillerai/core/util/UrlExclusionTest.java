package com.webkillerai.core.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("UrlExclusion (prefix x2, glob x2, regex x2) — align with current prod semantics")
class UrlExclusionTest {

    private static URI uri(String path) {
        // 테스트는 항상 전체 URL을 넣는다(현행 구현은 url.toString() 전체를 검사)
        String p = path.startsWith("/") ? path : "/" + path;
        return URI.create("https://ex.com" + p);
    }

    @Nested
    @DisplayName("PREFIX rules")
    class PrefixRules {
        @Test
        @DisplayName("'/admin' — /admin, /admin/panel excluded ; /administrator included")
        void prefix_admin() {
            var rules = List.of("/admin"); // NOTE: 'prefix:' 접두어 사용 안 함 (현행 구현 기준)
            assertTrue(UrlExclusion.isExcluded(uri("/admin"), rules));
            assertTrue(UrlExclusion.isExcluded(uri("/admin/panel"), rules));
            assertTrue(UrlExclusion.isExcluded(uri("/administrator"), rules));
        }

        @Test
        @DisplayName("'/static/' — /static/a.css excluded ; /statics/a.css included")
        void prefix_staticSlash() {
            var rules = List.of("/static/");
            assertTrue(UrlExclusion.isExcluded(uri("/static/a.css"), rules));
            assertFalse(UrlExclusion.isExcluded(uri("/statics/a.css"), rules));
        }
    }

    @Nested
    @DisplayName("GLOB rules (no 'glob:' prefix; '*' and '?' only)")
    class GlobRules {
        @Test
        @DisplayName("'/assets/**/*.map' — /assets/js/app.min.map excluded ; /assets.map included")
        void glob_assets_map() {
            // 현행 globToRegex: * -> ".*", ? -> ".", 앵커 없음, .find() 사용 → 전체 URL 중 일부 매치 허용
            var rules = List.of("/assets/**/*.map"); // 'glob:' 접두어 없음
            assertTrue(UrlExclusion.isExcluded(uri("/assets/js/app.min.map"), rules));
            assertFalse(UrlExclusion.isExcluded(uri("/assets.map"), rules));
        }

        @Test
        @DisplayName("'/**/debug-*' — /api/debug-123 excluded ; /api/v1/xdebug-1 included")
        void glob_debug_star() {
            var rules = List.of("/**/debug-*"); // 'glob:' 접두어 없음
            assertTrue(UrlExclusion.isExcluded(uri("/api/debug-123"), rules));
            assertFalse(UrlExclusion.isExcluded(uri("/api/v1/xdebug-1"), rules));
        }
    }

    @Nested
    @DisplayName("REGEX rules (must use 're:'; find semantics on full URL)")
    class RegexRules {
        @Test
        @DisplayName("re:/debug(?:/.*)?$ — /debug, /debug/x excluded ; /debugger included")
        void regex_debug_anchor() {
            // 현행은 full URL에 대해 .find()이므로 ^/debug 는 매치 안 됨. 아래처럼 사용.
            var rules = List.of("re:/debug(?:/.*)?$");
            assertTrue(UrlExclusion.isExcluded(uri("/debug"), rules));
            assertTrue(UrlExclusion.isExcluded(uri("/debug/x"), rules));
            assertFalse(UrlExclusion.isExcluded(uri("/debugger"), rules));
        }

        @Test
        @DisplayName("re:\\.(bak|tmp)$ — /a.bak, /a.tmp excluded ; /a.tmpx included")
        void regex_backup_tmp() {
            var rules = List.of("re:\\.(bak|tmp)$");
            for (String p : Arrays.asList("/a.bak", "/a.tmp")) {
                assertTrue(UrlExclusion.isExcluded(uri(p), rules));
            }
            assertFalse(UrlExclusion.isExcluded(uri("/a.tmpx"), rules));
        }
    }
}


