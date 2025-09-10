package com.webkillerai.core.util;

@FunctionalInterface
public interface ProgressListener {
    /**
     * @param progress 0.0~1.0 (모르면 0.0)
     * @param phase    "crawl" | "analyze" | "scan" | "export" 등
     * @param done     처리 수(모르면 -1)
     * @param total    전체 수(모르면 -1)
     */
    void onProgress(double progress, String phase, long done, long total);

    ProgressListener NONE = (p, phase, d, t) -> {};
}
