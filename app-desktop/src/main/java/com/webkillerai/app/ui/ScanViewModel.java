package com.webkillerai.app.ui;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.service.ScanService;
import com.webkillerai.core.service.export.HtmlReportExporter;
import com.webkillerai.core.service.export.PdfReportExporter;
import com.webkillerai.core.util.YamlConfigLoader;

import javafx.application.Platform;
import javafx.beans.property.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.concurrent.Task;
import javafx.concurrent.Worker;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/** ViewModel: 입력값 바인딩 + 실제 스캔 연결 + 결과 저장(복사 용이 경로 제공) + 이슈 필터/정렬 모델 */
public class ScanViewModel {

    // ----- 입력/진행 상태 -----
    private final StringProperty target = new SimpleStringProperty("");
    private final IntegerProperty maxDepth = new SimpleIntegerProperty(2);
    private final BooleanProperty running = new SimpleBooleanProperty(false);
    private final DoubleProperty progress = new SimpleDoubleProperty(0.0);
    private final StringProperty message = new SimpleStringProperty("");
    private final StringProperty lastSavedPath = new SimpleStringProperty(""); // UI 복사용 경로

    // scan.yml에서 읽은 기본설정 보관
    private ScanConfig loadedCfg = ScanConfig.defaults();

    // ----- 이슈 리스트 & 필터/정렬 모델 -----
    private final ObservableList<VulnResult> allIssues = FXCollections.observableArrayList();
    private final FilteredList<VulnResult> filteredIssues = new FilteredList<>(allIssues, it -> true);
    private final SortedList<VulnResult> sortedIssues = new SortedList<>(filteredIssues);

    // 검색/필터/정렬 토글
    private final StringProperty query = new SimpleStringProperty("");
    private final BooleanProperty highOn = new SimpleBooleanProperty(true);
    private final BooleanProperty medOn  = new SimpleBooleanProperty(true);
    private final BooleanProperty lowOn  = new SimpleBooleanProperty(true);
    private final BooleanProperty severityDesc = new SimpleBooleanProperty(true); // HIGH→LOW 우선

    // Open report 우선순위용 경로(HTML 우선 → JSON)
    private final StringProperty lastHtmlPath = new SimpleStringProperty("");
    private final StringProperty lastJsonPath = new SimpleStringProperty("");

    public ScanViewModel() {
        loadDefaultsFromYamlIfPresent();

        // 검색/필터/정렬 동작 연결
        query.addListener((o, ov, nv) -> refreshPredicate());
        highOn.addListener((o, ov, nv) -> refreshPredicate());
        medOn.addListener((o, ov, nv) -> refreshPredicate());
        lowOn.addListener((o, ov, nv) -> refreshPredicate());
        severityDesc.addListener((o, ov, nv) -> refreshComparator());
        refreshPredicate();
        refreshComparator();
    }

    // -------- 초기값 로드 --------
    public void loadDefaultsFromYamlIfPresent() {
        try {
            ScanConfig cfg = YamlConfigLoader.loadDefault();
            loadedCfg = cfg;
            if (cfg.getTarget() != null) setTarget(cfg.getTarget());
            setMaxDepth(cfg.getMaxDepth());
            setMessage("Loaded defaults from scan.yml");
        } catch (IOException e) {
            loadedCfg = ScanConfig.defaults();
            setMessage("Using in-app defaults");
        }
    }

    // -------- 입력 검증 --------
    public boolean validateInputs() {
        String t = getTarget();
        if (t == null || t.isBlank()) {
            setMessage("Target URL is required.");
            return false;
        }
        if (getMaxDepth() < 0) {
            setMessage("Depth must be >= 0.");
            return false;
        }
        return true;
    }

    // -------- 스캔 실행(비동기) + 결과 저장(JSON/HTML/PDF 옵션 반영) --------
    public void startMockScan(Runnable onDone) {
        if (!validateInputs() || isRunning()) return;

        final String startedIso = Instant.now().toString();

        Task<Path> task = new Task<>() {
            @Override protected Path call() throws Exception {
                // 상태 메시지
                ScanConfig effective = buildEffectiveConfig();
                updateMessage(String.format("Scanning … (RPS=%d, CC=%d)", effective.getRps(), effective.getConcurrency()));
                updateProgress(0, 100);

                // 1) 진행바 모의
                for (int i = 1; i <= 60; i++) {
                    if (isCancelled()) break;
                    Thread.sleep(10);
                    updateProgress(i, 100);
                }

                // 2) 실제 스캔
                ScanService svc = new ScanService(effective);
                List<VulnResult> results = svc.run();

                // ▼ 결과를 ViewModel 리스트에 반영
                Platform.runLater(() -> allIssues.setAll(results));

                // 3) 진행바 마무리
                for (int i = 61; i <= 100; i++) {
                    if (isCancelled()) break;
                    Thread.sleep(5);
                    updateProgress(i, 100);
                }

                // 4) 저장 (경로 반환)
                Path outFile = saveResults(results, startedIso, effective, svc);
                updateMessage("Saved: " + outFile.toAbsolutePath() + " (" + results.size() + " issues)");
                return outFile;
            }

            @Override protected void scheduled() { running.set(true); }

            @Override protected void succeeded() {
                running.set(false);
                Path out = getValue();
                if (out != null) lastSavedPath.set(out.toAbsolutePath().toString());
                if (onDone != null) onDone.run();
            }

            @Override protected void failed() {
                running.set(false);
                lastSavedPath.set("");
                updateMessage("Scan failed: " + getException());
                if (onDone != null) onDone.run();
            }

            @Override protected void cancelled() {
                running.set(false);
                lastSavedPath.set("");
                updateMessage("Scan cancelled.");
                if (onDone != null) onDone.run();
            }
        };

        // 바인딩 (message는 task.messageProperty()에 바인딩됨 → setMessage 금지)
        progress.bind(task.progressProperty());
        message.bind(task.messageProperty());

        Thread t = new Thread(task, "scan");
        t.setDaemon(true);
        t.start();

        // 터미널 상태에서 바인딩 해제
        task.stateProperty().addListener((obs, oldState, newState) -> {
            if (newState == Worker.State.SUCCEEDED
                    || newState == Worker.State.FAILED
                    || newState == Worker.State.CANCELLED) {
                Platform.runLater(() -> {
                    progress.unbind();
                    message.unbind();
                });
            }
        });
    }

    private ScanConfig buildEffectiveConfig() {
        // loadedCfg 값을 복사하고, UI 입력으로 target/maxDepth만 덮어쓰기
        ScanConfig cfg = ScanConfig.defaults()
                .setTarget(getTarget())
                .setMaxDepth(getMaxDepth())
                .setSameDomainOnly(loadedCfg.isSameDomainOnly())
                .setMode(loadedCfg.getMode())
                .setTimeout(loadedCfg.getTimeout())
                .setConcurrency(loadedCfg.getConcurrency())
                .setFollowRedirects(loadedCfg.isFollowRedirects())
                .setOutputDir(loadedCfg.getOutputDir())
                .setOutputFormat(loadedCfg.getOutputFormat());
        cfg.setRps(loadedCfg.getRps());
        cfg.validate();
        return cfg;
    }

    // 결과 저장: out/reports/<host>/scan-<slug>-<YYYYMMDD-HHmm>.{json|html|pdf}
    private Path saveResults(List<VulnResult> results, String startedIso, ScanConfig effective,
                             ScanService svc) throws Exception {
        Path baseDir = (effective.getOutputDir() == null ? Path.of("out") : effective.getOutputDir());

        // output.format 유연 파싱
        Set<String> formats = resolveFormats(effective);

        Path last = null;

        if (formats.contains("json")) {
            Path json = new com.webkillerai.core.service.export.JsonReportExporter()
                    .withRuntime(svc) // 런타임/통계 주입
                    .export(baseDir, effective, results, startedIso);
            last = json;
            lastJsonPath.set(json.toAbsolutePath().toString()); // HTML 없을 때 fallback
        }

        if (formats.contains("html")) {
            Path html = new HtmlReportExporter()
                    // .withStats(svc.getStats()) // 필요 시 활성화
                    .export(baseDir, effective, results, startedIso);
            last = html; // UI엔 HTML 경로를 우선 표시
            lastHtmlPath.set(html.toAbsolutePath().toString());
        }

        if (formats.contains("pdf")) {
            if (PdfReportExporter.isAvailable()) {
                Path pdf = new PdfReportExporter().export(baseDir, effective, results, startedIso);
                last = pdf;
            } else {
                // updateMessage("PDF exporter unavailable (missing openhtmltopdf deps)");
            }
        }

        // 포맷이 비어있거나 엣지 케이스 대비: 최소한 JSON 하나는 보장
        if (last == null) {
            Path json = new com.webkillerai.core.service.export.JsonReportExporter()
                    .withRuntime(svc)
                    .export(baseDir, effective, results, startedIso);
            last = json;
            lastJsonPath.set(json.toAbsolutePath().toString());
        }
        return last;
    }

    /** ScanConfig에서 output.format 값을 유연하게 추출해 Set으로 반환 */
    private static Set<String> resolveFormats(ScanConfig cfg) {
        Object fmtObj = null;

        // 1) getOutputFormat() 시도
        try {
            var m = cfg.getClass().getMethod("getOutputFormat");
            fmtObj = m.invoke(cfg);
        } catch (Exception ignore) {}

        // 2) 없으면 getOutput().getFormat() 시도
        if (fmtObj == null) {
            try {
                Object out = cfg.getClass().getMethod("getOutput").invoke(cfg);
                if (out != null) {
                    try {
                        fmtObj = out.getClass().getMethod("getFormat").invoke(out);
                    } catch (Exception ignore) {}
                }
            } catch (Exception ignore) {}
        }
        return parseFormatsFlexible(fmtObj);
    }

    /** "json,html,pdf" | enum | 래퍼 | 컬렉션 등 → 소문자 Set. 없으면 기본 "json" */
    private static Set<String> parseFormatsFlexible(Object fmt) {
        if (fmt == null) return Set.of("json");

        // 1) 문자열류
        if (fmt instanceof CharSequence) {
            return splitFormats(fmt.toString());
        }

        // 2) 컬렉션 (예: List<String> or List<Enum>)
        if (fmt instanceof Collection<?> col) {
            StringBuilder sb = new StringBuilder();
            for (Object o : col) {
                if (sb.length() > 0) sb.append(',');
                sb.append(String.valueOf(o));
            }
            return splitFormats(sb.toString());
        }

        // 3) 래퍼/레코드/다른 타입: getFormat() 리플렉션 우선, 없으면 toString()
        try {
            var m = fmt.getClass().getMethod("getFormat");
            Object inner = m.invoke(fmt);
            if (inner != null) return parseFormatsFlexible(inner);
        } catch (Exception ignore) {}

        // 4) enum 등: 이름/문자열로 처리
        return splitFormats(String.valueOf(fmt));
    }

    /** "a,b,c" → ["a","b","c"] (소문자 트림), 비어있으면 ["json"] */
    private static Set<String> splitFormats(String s) {
        if (s == null || s.isBlank()) return Set.of("json");
        var set = new LinkedHashSet<String>();
        for (String p : s.split(",")) {
            String v = p.trim().toLowerCase(Locale.ROOT);
            if (!v.isEmpty()) set.add(v);
        }
        return set.isEmpty() ? Set.of("json") : set;
    }

    // ----- 필터/정렬 로직 -----
    private void refreshPredicate(){
        String q = Optional.ofNullable(query.get()).orElse("").trim().toLowerCase(Locale.ROOT);
        EnumSet<Severity> allowed = EnumSet.noneOf(Severity.class);
        if (highOn.get()) allowed.add(Severity.HIGH);
        if (medOn.get())  allowed.add(Severity.MEDIUM);
        if (lowOn.get())  allowed.add(Severity.LOW);
        // INFO/CRITICAL은 토글 범위 밖 (요구사항 기준)

        filteredIssues.setPredicate(v -> {
            if (!allowed.contains(v.getSeverity())) return false;
            if (q.isEmpty()) return true;
            return s(v.getUrl()).contains(q)
                || s(v.getIssueType() == null ? null : v.getIssueType().name()).contains(q)
                || s(v.getEvidence()).contains(q);
        });
    }

    private void refreshComparator(){
        // severityDesc=true → HIGH→LOW 우선
        Comparator<Severity> sevWeight = Comparator.comparingInt(s -> switch (s){
            case HIGH -> 3; case MEDIUM -> 2; case LOW -> 1; default -> 0;
        });
        Comparator<Severity> sevCmp = severityDesc.get() ? sevWeight.reversed() : sevWeight;
        sortedIssues.setComparator(
            Comparator.comparing(VulnResult::getSeverity, sevCmp)
                      .thenComparing(v -> Optional.ofNullable(v.getIssueType()).map(Enum::name).orElse(""))
                      .thenComparing(v -> Optional.ofNullable(v.getUrl()).map(Object::toString).orElse(""))
        );
    }

    private static String s(Object x){ return x==null? "": x.toString().toLowerCase(Locale.ROOT); }

    // ----- 컨트롤러 바인딩용 공개 API -----
    // 테이블 데이터 소스
    public SortedList<VulnResult> sortedIssues() { return sortedIssues; }

    // 검색/토글 바인딩
    public StringProperty queryProperty(){ return query; }
    public BooleanProperty highOnProperty(){ return highOn; }
    public BooleanProperty medOnProperty(){ return medOn; }
    public BooleanProperty lowOnProperty(){ return lowOn; }
    public BooleanProperty severityDescProperty(){ return severityDesc; }

    // 마지막 산출물 경로(HTML 우선) - 컨트롤러 Open 버튼에서 사용
    public Optional<Path> preferredReport(){
        if (!lastHtmlPath.get().isBlank()) return Optional.of(Path.of(lastHtmlPath.get()));
        if (!lastJsonPath.get().isBlank()) return Optional.of(Path.of(lastJsonPath.get()));
        if (lastSavedPath.get()!=null && !lastSavedPath.get().isBlank()) return Optional.of(Path.of(lastSavedPath.get()));
        return Optional.empty();
    }
    public ReadOnlyStringProperty lastHtmlPathProperty(){ return lastHtmlPath; }
    public ReadOnlyStringProperty lastJsonPathProperty(){ return lastJsonPath; }

    // ----- 기존 getters/setters/properties -----
    public String getTarget() { return target.get(); }
    public void setTarget(String v) { target.set(v); }
    public StringProperty targetProperty() { return target; }

    public int getMaxDepth() { return maxDepth.get(); }
    public void setMaxDepth(int v) { maxDepth.set(v); }
    public IntegerProperty maxDepthProperty() { return maxDepth; }

    public boolean isRunning() { return running.get(); }
    public ReadOnlyBooleanProperty runningProperty() { return running; }

    public double getProgress() { return progress.get(); }
    public ReadOnlyDoubleProperty progressProperty() { return progress; }

    public String getMessage() { return message.get(); }
    public void setMessage(String v) { message.set(v); }
    public StringProperty messageProperty() { return message; }

    public ReadOnlyStringProperty lastSavedPathProperty() { return lastSavedPath; }
}

