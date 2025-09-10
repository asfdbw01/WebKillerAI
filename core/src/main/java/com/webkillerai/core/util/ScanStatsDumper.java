package com.webkillerai.core.util;

import com.webkillerai.core.model.ScanStats;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.function.Supplier;

/**
 * ScanStats 스냅샷을 주기적으로 NDJSON으로 기록한다.
 * - Snapshot은 public final 필드 사용(requestsTotal, retriesTotal, avgLatencyMs, maxObservedConcurrency)
 * - 단일 writer 유지(Append), 윈도우 락/성능 문제 완화
 * - NDJSON: 라인당 순수 JSON만 기록
 */
public final class ScanStatsDumper implements AutoCloseable {

    private final Supplier<ScanStats.Snapshot> snapshotSupplier;
    private final Path outFile;
    private final long periodMs;

    private final ScheduledExecutorService ses;
    private volatile ScheduledFuture<?> future;
    private BufferedWriter writer;
    private final Object lock = new Object();
    private volatile boolean started = false;
    private volatile boolean closed  = false;

    public ScanStatsDumper(Supplier<ScanStats.Snapshot> snapshotSupplier,
                           Path outDir,
                           String filename,
                           long periodMs) {
        this.snapshotSupplier = Objects.requireNonNull(snapshotSupplier, "snapshotSupplier");
        this.outFile = Objects.requireNonNull(outDir, "outDir").resolve(Objects.requireNonNull(filename, "filename"));
        this.periodMs = Math.max(500L, periodMs); // 최소 0.5s
        this.ses = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "scanstats-dumper");
            t.setDaemon(true);
            return t;
        });
    }

    /** 주기적 기록 시작(중복 호출 안전) */
    public void start() throws IOException {
        if (started || closed) return;
        synchronized (lock) {
            if (started || closed) return;

            Files.createDirectories(outFile.getParent());
            writer = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);

            future = ses.scheduleAtFixedRate(this::safeWriteOnce, 0L, periodMs, TimeUnit.MILLISECONDS);
            started = true;
        }
    }

    private void safeWriteOnce() {
        try {
            writeOnce();
        } catch (Throwable t) {
            // 가벼운 복구: 1회 재시도
            try { writeOnce(); } catch (Throwable ignore) {}
        }
    }

    private void writeOnce() throws IOException {
        if (closed) return;
        ScanStats.Snapshot s = snapshotSupplier.get();
        if (s == null) return;

        String json = toNdjson(s);
        synchronized (lock) {
            if (writer == null) return;
            writer.write(json);
            writer.newLine();
            writer.flush();
        }
    }

    private static String toNdjson(ScanStats.Snapshot s) {
        // {"ts": "...", "requestsTotal": N, "retriesTotal": N, "avgLatencyMs": N, "maxObservedConcurrency": N}
        StringBuilder b = new StringBuilder(200);
        b.append('{');
        kv(b, "ts", Instant.now().toString());
        kv(b, "requestsTotal", s.requestsTotal);
        kv(b, "retriesTotal",  s.retriesTotal);
        kv(b, "avgLatencyMs",  s.avgLatencyMs);
        kv(b, "maxObservedConcurrency", s.maxObservedConcurrency);
        // 마지막 콤마 제거
        if (b.charAt(b.length() - 1) == ',') b.setLength(b.length() - 1);
        b.append('}');
        return b.toString();
    }

    private static void kv(StringBuilder b, String k, Object v) {
        b.append('"').append(esc(k)).append('"').append(':');
        if (v == null) b.append("null");
        else if (v instanceof Number || v instanceof Boolean) b.append(v);
        else b.append('"').append(esc(String.valueOf(v))).append('"');
        b.append(',');
    }

    private static String esc(String s) {
        StringBuilder r = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> r.append("\\\"");
                case '\\' -> r.append("\\\\");
                case '\n' -> r.append("\\n");
                case '\r' -> r.append("\\r");
                case '\t' -> r.append("\\t");
                default   -> r.append(c);
            }
        }
        return r.toString();
    }

    /** 중지 및 자원 해제(다시 start()는 비권장) */
    public void stop() { close(); }

    @Override
    public void close() {
        if (closed) return;
        synchronized (lock) {
            if (closed) return;
            closed = true;

            if (future != null) {
                future.cancel(false);
                future = null;
            }
            ses.shutdownNow();

            if (writer != null) {
                try { writer.flush(); } catch (IOException ignore) {}
                try { writer.close(); } catch (IOException ignore) {}
                writer = null;
            }
        }
    }
}
