package com.webkillerai.app.ui;

import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.app.ui.preset.AdvancedFilterPreset;
import com.webkillerai.app.ui.preset.AdvancedFilterPresetIO;

import javafx.animation.FadeTransition;               // ★ 추가
import javafx.animation.PauseTransition;             // ★ 추가
import javafx.beans.binding.Bindings;
import javafx.beans.property.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableSet;
import javafx.collections.SetChangeListener;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import javafx.util.Duration;                          // ★ 추가

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.prefs.Preferences;

/** Advanced filter bar as a reusable control (loads its own FXML). */
public final class AdvancedFilterBar extends VBox {

    @FXML private MenuButton typeMenu;
    @FXML private MenuButton sevMenu;
    @FXML private ToggleButton btnAnd, btnOr;
    @FXML private TextField tfUrl, tfRisk, tfEvi;
    @FXML private DatePicker dpFrom, dpTo;
    @FXML private Button btnReset;
    @FXML private FlowPane chipsPane;

    // ★ 프리셋 파일 입/출력 버튼 (FXML에도 fx:id 추가 필요)
    @FXML private Button btnExportPreset;
    @FXML private Button btnImportPreset;

    public enum BoolMode { AND, OR }

    private final ObservableSet<String> types = FXCollections.observableSet();
    private final ObservableSet<Severity> severities = FXCollections.observableSet();
    private final ObjectProperty<BoolMode> mode = new SimpleObjectProperty<>(BoolMode.AND);
    private final StringProperty urlQ = new SimpleStringProperty("");
    private final StringProperty eviQ = new SimpleStringProperty("");
    private final StringProperty riskExpr = new SimpleStringProperty("");
    private final ObjectProperty<LocalDate> from = new SimpleObjectProperty<>(null);
    private final ObjectProperty<LocalDate> to   = new SimpleObjectProperty<>(null);

    private Consumer<Predicate<VulnResult>> predicateSink = p -> {};

    // ---- Preferences ----
    private Preferences prefs = Preferences.userRoot().node("/com/webkillerai/app");
    private boolean loadingPrefs = false;

    private static final String NS = "ui.filter.";
    private static final String K_TYPE = NS + "type";
    private static final String K_SEV = NS + "severity";
    private static final String K_MODE = NS + "mode";            // AND|OR
    private static final String K_URL  = NS + "url.contains";
    private static final String K_EVI  = NS + "evi.contains";
    private static final String K_RISK = NS + "risk.expr";
    private static final String K_FROM = NS + "date.from";       // yyyy-MM-dd
    private static final String K_TO   = NS + "date.to";         // yyyy-MM-dd
    private static final String K_PRESET_LASTDIR = NS + "preset.lastDir"; // 파일 다이얼로그 폴더 기억

    // ---- Preset I/O ----
    private final AdvancedFilterPresetIO presetIO = new AdvancedFilterPresetIO();

    // ---- Micro-UX: Debounce ----
    private final Map<Node, PauseTransition> debounceMap = new HashMap<>(); // ★ 추가
    private static final Duration DEBOUNCE = Duration.millis(150);          // ★ 추가

    public AdvancedFilterBar() {
        FXMLLoader fx = new FXMLLoader(getClass().getResource("AdvancedFilterBar.fxml"));
        fx.setRoot(this);
        fx.setController(this);
        try { fx.load(); } catch (IOException e) { throw new RuntimeException("Load AdvancedFilterBar.fxml failed", e); }
    }

    /** 테스트/커스터마이징용: 다른 노드로 저장하고 싶을 때 호출 */
    public void setPreferencesNode(Preferences node) {
        this.prefs = (node != null) ? node : Preferences.userRoot().node("/com/webkillerai/app");
    }

    @FXML
    private void initialize() {
        // IssueType 멀티선택 (리플렉션; 없으면 건너뜀)
        try {
            Class<?> it = Class.forName("com.webkillerai.core.model.IssueType");
            Object[] all = it.getEnumConstants();
            if (all != null) {
                for (Object e : all) {
                    String label = (e instanceof Enum<?> en) ? en.name() : String.valueOf(e);
                    addCheck(typeMenu, label, types);
                }
            }
        } catch (ClassNotFoundException ignore) {}

        // Severity 멀티선택
        for (Severity s : Severity.values()) addCheck(sevMenu, s.name(), severities);

        // AND/OR 토글
        btnAnd.selectedProperty().addListener((obs, was, sel) -> { if (sel) mode.set(BoolMode.AND); });
        btnOr.selectedProperty().addListener((obs, was, sel) -> { if (sel) mode.set(BoolMode.OR); });

        // 바인딩
        urlQ.bindBidirectional(tfUrl.textProperty());
        eviQ.bindBidirectional(tfEvi.textProperty());
        riskExpr.bindBidirectional(tfRisk.textProperty());
        from.bindBidirectional(dpFrom.valueProperty());
        to.bindBidirectional(dpTo.valueProperty());

        // Reset
        btnReset.setOnAction(e -> reset());

        // 프리셋 파일 I/O 버튼
        if (btnExportPreset != null) btnExportPreset.setOnAction(e -> onExportPresetFile());
        if (btnImportPreset != null) btnImportPreset.setOnAction(e -> onImportPresetFile());

        // chips 표시 여부 (+ 레이아웃 제외)
        chipsPane.visibleProperty().bind(Bindings.createBooleanBinding(
                () -> !types.isEmpty() || !severities.isEmpty()
                        || !blank(urlQ.get()) || !blank(eviQ.get())
                        || !blank(riskExpr.get()) || from.get()!=null || to.get()!=null,
                Bindings.size(types),
                Bindings.size(severities),
                urlQ, eviQ, riskExpr, from, to
        ));
        chipsPane.managedProperty().bind(chipsPane.visibleProperty());

        // ---- 변경 포인트: 발행 타이밍 관리 ----
        // Set 계열(타입/심각도/모드)은 즉시 반영이 자연스러워 기존처럼 즉시 publish
        types.addListener((SetChangeListener<String>) c -> publish());
        severities.addListener((SetChangeListener<Severity>) c -> publish());
        mode.addListener((o, a, b) -> publish());

        // 텍스트/날짜/메뉴 닫힘은 디바운스
        installDebounce(); // ★ 추가

        // Preferences 로드 → UI/상태 반영
        loadFromPrefs();

        // Risk 입력 검증(보더/툴팁) 설치
        installRiskValidation();

        // 초기 1회 발행
        publish();
    }

    /** 부모 컨트롤러에서 등록: 필터 변경 시 전달받을 sink */
    public void setPredicateSink(Consumer<Predicate<VulnResult>> sink) {
        this.predicateSink = (sink != null) ? sink : p -> {};
        this.predicateSink.accept(buildPredicate());
        renderChips();
    }

    // ---------- Export Preset (파일) ----------
    @FXML
    private void onExportPresetFile() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Export Advanced Filter Preset");
        setInitialDir(fc);
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("JSON Files", "*.json"));

        Window owner = (btnExportPreset != null && btnExportPreset.getScene() != null)
                ? btnExportPreset.getScene().getWindow() : null;
        File f = fc.showSaveDialog(owner);
        if (f == null) return;

        try {
            AdvancedFilterPreset p = buildPresetFromState();
            Path out = f.toPath();
            if (!out.toString().toLowerCase(Locale.ROOT).endsWith(".json")) {
                out = out.resolveSibling(out.getFileName().toString() + ".json");
            }
            presetIO.exportToFile(p, out);
            saveLastDir(out.toFile());
            System.out.println("[AF] Preset exported: " + out.toAbsolutePath());
        } catch (Exception ex) {
            Alert a = new Alert(Alert.AlertType.ERROR, ex.getMessage());
            a.setHeaderText("Export failed");
            a.showAndWait();
        }
    }

    // ---------- Import Preset (파일) ----------
    @FXML
    private void onImportPresetFile() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Import Advanced Filter Preset");
        setInitialDir(fc);
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("JSON Files", "*.json"));

        Window owner = (btnImportPreset != null && btnImportPreset.getScene() != null)
                ? btnImportPreset.getScene().getWindow() : null;
        File f = fc.showOpenDialog(owner);
        if (f == null) return;

        try {
            AdvancedFilterPreset p = presetIO.importFromFile(f.toPath());
            saveLastDir(f);
            applyPreset(p);
            System.out.println("[AF] Preset imported: " + f.getAbsolutePath());
        } catch (Exception ex) {
            Alert a = new Alert(Alert.AlertType.ERROR, ex.getMessage());
            a.setHeaderText("Import failed");
            a.showAndWait();
        }
    }

    // ---------- 외부 공개용 프리셋 API ----------
    /** 현재 UI 상태를 프리셋 객체로 스냅샷 */
    public AdvancedFilterPreset snapshotPreset() {
        return buildPresetFromState();
    }

    /** 프리셋 → UI 상태 적용 (외부에서도 호출 가능) */
    public void applyPreset(AdvancedFilterPreset p) {
        if (p == null) return;
        loadingPrefs = true;
        try {
            // 초기화
            types.clear(); severities.clear();
            tfUrl.clear(); tfEvi.clear(); tfRisk.clear();
            dpFrom.setValue(null); dpTo.setValue(null);
            btnAnd.setSelected(true); mode.set(BoolMode.AND);
            clearChecks(typeMenu); clearChecks(sevMenu);

            // 로직
            String logic = (p.logic == null ? "AND" : p.logic);
            if ("OR".equalsIgnoreCase(logic)) { btnOr.setSelected(true); mode.set(BoolMode.OR); }
            else { btnAnd.setSelected(true); mode.set(BoolMode.AND); }

            // 타입/심각도
            if (p.types != null) types.addAll(p.types);
            if (p.severities != null) {
                for (String sv : p.severities) {
                    try { severities.add(Severity.valueOf(sv)); } catch (Exception ignore) {}
                }
            }

            // 메뉴 체크 UI 반영
            applyChecksFromSet(typeMenu, name -> types.contains(name));
            applyChecksFromSet(sevMenu,  name -> {
                try { return severities.contains(Severity.valueOf(name)); }
                catch (Exception e) { return false; }
            });

            // 문자열
            urlQ.set(opt(p.urlContains));
            eviQ.set(opt(p.evidenceContains));
            riskExpr.set(opt(p.riskExpr));

            // 날짜 (dateTo는 export 시 +1일 00:00(배타)로 저장 → UI엔 -1일 복원)
            ZoneId z = ZoneId.systemDefault();
            if (p.dateFrom != null) dpFrom.setValue(LocalDate.ofInstant(p.dateFrom, z));
            if (p.dateTo   != null) dpTo.setValue(LocalDate.ofInstant(p.dateTo, z).minusDays(1));

        } finally {
            loadingPrefs = false;
            publish(); // 칩/프리뷰/프레디킷/Prefs 저장까지 반영
        }
    }

    // ---------- 내부: 프리셋 빌더 ----------
    private AdvancedFilterPreset buildPresetFromState() {
        AdvancedFilterPreset p = new AdvancedFilterPreset();
        p.v = "1";
        p.name = null; // 필요 시 UI에서 이름 받도록 확장
        p.logic = (btnAnd != null && btnAnd.isSelected()) ? "AND" : "OR";
        p.types = new ArrayList<>(types);
        // Severity → 이름(String)
        List<String> sevNames = new ArrayList<>();
        for (Severity s : severities) sevNames.add(s.name());
        p.severities = sevNames;
        p.urlContains = opt(urlQ.get());
        p.evidenceContains = opt(eviQ.get());
        p.riskExpr = opt(riskExpr.get());
        if (from.get() != null) {
            p.dateFrom = from.get().atStartOfDay(ZoneId.systemDefault()).toInstant();
        }
        if (to.get() != null) {
            // exclusive 저장: To 당일까지 포함하려면 +1일 00:00 보관
            p.dateTo = to.get().plusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant();
        }
        return p;
    }

    // ---------- 파일 다이얼로그 폴더 기억 ----------
    private void setInitialDir(FileChooser fc) {
        String last = prefs.get(K_PRESET_LASTDIR, null);
        if (last != null) {
            File d = new File(last);
            if (d.exists() && d.isDirectory()) fc.setInitialDirectory(d);
        }
    }
    private void saveLastDir(File f) {
        File dir = f.getParentFile();
        if (dir != null) prefs.put(K_PRESET_LASTDIR, dir.getAbsolutePath());
    }

    // ---------- 내부 유틸 ----------
    private <T> void addCheck(MenuButton menu, String label, Set<T> set) {
        var item = new CheckMenuItem(label);
        item.selectedProperty().addListener((o, old, nowSel) -> {
            if (nowSel) set.add(convert(set, label));
            else set.remove(convert(set, label));
        });
        menu.getItems().add(item);
    }
    @SuppressWarnings("unchecked")
    private <T> T convert(Set<T> set, String s) {
        if (set == this.severities) return (T) Severity.valueOf(s);
        return (T) s;
    }
    private void reset() {
        loadingPrefs = true;
        types.clear(); severities.clear();
        tfUrl.clear(); tfRisk.clear(); tfEvi.clear();
        dpFrom.setValue(null); dpTo.setValue(null);
        btnAnd.setSelected(true);
        clearChecks(typeMenu); clearChecks(sevMenu);
        loadingPrefs = false;
        publish();
    }
    private void clearChecks(MenuButton menu) {
        for (var it : menu.getItems()) {
            if (it instanceof CheckMenuItem cmi) cmi.setSelected(false);
        }
    }
    private void publish() {
        if (loadingPrefs) return;
        predicateSink.accept(buildPredicate());
        renderChips();
        saveToPrefs();
    }

    private Predicate<VulnResult> buildPredicate() {
        Set<String> typeSnap = Set.copyOf(types);
        Set<Severity> sevSnap = Set.copyOf(severities);
        BoolMode modeSnap = mode.get();
        String urlNeedle = optLower(urlQ.get());
        String eviNeedle = optLower(eviQ.get());
        String riskExprSnap = (riskExpr.get() == null ? "" : riskExpr.get().trim());
        LocalDate fromSnap = from.get();
        LocalDate toSnap = to.get();
        RiskPredicate riskP = RiskPredicate.parse(riskExprSnap);

        final ZoneId z = ZoneId.systemDefault();
        final Instant lo = (fromSnap == null) ? Instant.EPOCH : fromSnap.atStartOfDay(z).toInstant();
        final Instant hi = (toSnap == null)
                ? Instant.ofEpochMilli(Long.MAX_VALUE)
                : toSnap.plusDays(1).atStartOfDay(z).toInstant();

        List<Predicate<VulnResult>> active = new ArrayList<>(6);

        if (!typeSnap.isEmpty()) {
            active.add(v -> v.getIssueType() != null && typeSnap.contains(v.getIssueType().name()));
        }
        if (!sevSnap.isEmpty()) {
            active.add(v -> v.getSeverity() != null && sevSnap.contains(v.getSeverity()));
        }
        if (!urlNeedle.isEmpty()) {
            active.add(v -> v.getUrl() != null
                    && v.getUrl().toString().toLowerCase(Locale.ROOT).contains(urlNeedle));
        }
        if (!eviNeedle.isEmpty()) {
            active.add(v -> v.getEvidence() != null
                    && v.getEvidence().toLowerCase(Locale.ROOT).contains(eviNeedle));
        }
        if (!riskExprSnap.isBlank()) {
            active.add(v -> {
                int rv = (v.getRiskScore() != null) ? v.getRiskScore() : switch (v.getSeverity()) {
                    case INFO -> 10; case LOW -> 25; case MEDIUM -> 50; case HIGH -> 75; case CRITICAL -> 90;
                };
                return riskP.test(rv);
            });
        }
        if (!(fromSnap == null && toSnap == null)) {
            active.add(v -> {
                Instant t = (v.getDetectedAt() == null) ? Instant.EPOCH : v.getDetectedAt();
                return !t.isBefore(lo) && t.isBefore(hi);
            });
        }

        if (active.isEmpty()) return v -> true;

        if (modeSnap == BoolMode.AND) {
            return v -> {
                for (Predicate<VulnResult> p : active) if (!p.test(v)) return false;
                return true;
            };
        } else {
            return v -> {
                for (Predicate<VulnResult> p : active) if (p.test(v)) return true;
                return false;
            };
        }
    }

    private static String optLower(String s) { return (s == null) ? "" : s.toLowerCase(Locale.ROOT); }
    private static boolean blank(String s){ return s==null || s.isBlank(); }

    // ---------- Chips ----------
    private void renderChips() {
        chipsPane.getChildren().clear();

        for (String t : types) {
            chipsPane.getChildren().add(chip("Type: " + t, () -> types.remove(t)));
        }
        for (Severity s : severities) {
            chipsPane.getChildren().add(chip("Sev: " + s.name(), () -> severities.remove(s)));
        }
        if (!blank(urlQ.get())) {
            chipsPane.getChildren().add(chip("URL: " + urlQ.get(), () -> tfUrl.clear()));
        }
        if (!blank(eviQ.get())) {
            chipsPane.getChildren().add(chip("Evi: " + eviQ.get(), () -> tfEvi.clear()));
        }
        if (!blank(riskExpr.get())) {
            chipsPane.getChildren().add(chip("Risk: " + riskExpr.get(), () -> tfRisk.clear()));
        }
        if (from.get() != null) {
            chipsPane.getChildren().add(chip("From: " + from.get(), () -> dpFrom.setValue(null)));
        }
        if (to.get() != null) {
            chipsPane.getChildren().add(chip("To: " + to.get(), () -> dpTo.setValue(null)));
        }
        chipsPane.getChildren().add(chipReadOnly("Mode: " + mode.get().name()));
    }

    private Node chip(String text, Runnable onClose) {
        var lb = new Label(text);
        var btn = new Button("✕");
        btn.setOnAction(e -> onClose.run());
        var box = new HBox(6, lb, btn);
        box.setPadding(new Insets(4, 8, 4, 8));
        box.setStyle("-fx-background-color:-fx-control-inner-background; -fx-background-radius:12; "
                + "-fx-border-color:-fx-box-border; -fx-border-radius:12; -fx-alignment:CENTER_LEFT;");
        btn.setStyle("-fx-padding:2 6 2 6; -fx-background-radius:8;");
        lb.setStyle("-fx-font-weight:bold;");

        fadeIn(box); // ★ 추가: 칩 페이드인
        return box;
    }

    private Node chipReadOnly(String text) {
        var lb = new Label(text);
        var box = new HBox(6, lb);
        box.setPadding(new Insets(4, 8, 4, 8));
        box.setStyle("-fx-background-color:-fx-control-inner-background; -fx-background-radius:12; "
                + "-fx-border-color:-fx-box-border; -fx-border-radius:12; -fx-opacity:.8; "
                + "-fx-alignment:CENTER_LEFT;");
        lb.setStyle("-fx-font-weight:bold;");

        fadeIn(box); // ★ 추가: 칩 페이드인
        return box;
    }

    // ---------- Preferences load/save ----------
    private void loadFromPrefs() {
        loadingPrefs = true;
        try {
            types.clear();
            for (String t : splitCsv(prefs.get(K_TYPE, ""))) {
                if (!t.isBlank()) types.add(t.trim());
            }
            severities.clear();
            for (String s : splitCsv(prefs.get(K_SEV, ""))) {
                try { severities.add(Severity.valueOf(s.trim())); } catch (Exception ignore) {}
            }
            String m = prefs.get(K_MODE, "AND");
            if ("AND".equalsIgnoreCase(m)) { btnAnd.setSelected(true); mode.set(BoolMode.AND); }
            else { btnOr.setSelected(true); mode.set(BoolMode.OR); }

            urlQ.set(prefs.get(K_URL, ""));
            eviQ.set(prefs.get(K_EVI, ""));
            riskExpr.set(prefs.get(K_RISK, ""));
            from.set(parseDate(prefs.get(K_FROM, "")));
            to.set(parseDate(prefs.get(K_TO, "")));

            applyChecksFromSet(typeMenu, s -> types.contains(s));
            applyChecksFromSet(sevMenu, s -> {
                try { return severities.contains(Severity.valueOf(s)); }
                catch (Exception e) { return false; }
            });
        } finally {
            loadingPrefs = false;
        }
    }

    private void saveToPrefs() {
        if (loadingPrefs) return;
        prefs.put(K_TYPE, joinCsv(types));
        prefs.put(K_SEV, joinCsv(mapSeverityNames(severities)));
        prefs.put(K_MODE, mode.get().name());
        prefs.put(K_URL, opt(urlQ.get()));
        prefs.put(K_EVI, opt(eviQ.get()));
        prefs.put(K_RISK, opt(riskExpr.get()));
        prefs.put(K_FROM, from.get()==null ? "" : from.get().toString());
        prefs.put(K_TO,   to.get()==null ? "" : to.get().toString());
    }

    private static void applyChecksFromSet(MenuButton menu, java.util.function.Predicate<String> selected) {
        for (var it : menu.getItems()) {
            if (it instanceof CheckMenuItem cmi) {
                boolean sel = selected.test(cmi.getText());
                cmi.setSelected(sel);
            }
        }
    }

    private static String[] splitCsv(String csv) {
        return (csv == null || csv.isBlank()) ? new String[0] : csv.split("\\s*,\\s*");
    }
    private static String joinCsv(Collection<String> vals) {
        if (vals == null || vals.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (String s : vals) { if (sb.length() > 0) sb.append(','); sb.append(s); }
        return sb.toString();
    }
    private static Collection<String> mapSeverityNames(Collection<Severity> sevs) {
        List<String> out = new ArrayList<>();
        if (sevs != null) for (Severity s : sevs) out.add(s.name());
        return out;
    }
    private static String opt(String s){ return (s == null) ? "" : s; }
    private static LocalDate parseDate(String s) {
        try { return (s == null || s.isBlank()) ? null : LocalDate.parse(s); }
        catch (Exception e) { return null; }
    }

    // ---------- Risk expr parser & validation ----------
    private static final class RiskPredicate {
        private final java.util.function.Predicate<Integer> p;
        private RiskPredicate(java.util.function.Predicate<Integer> p){ this.p = p; }
        boolean test(int v){ return p.test(v); }

        static RiskPredicate parse(String expr) {
            String s = (expr==null?"":expr).trim().toLowerCase(Locale.ROOT);
            if (s.matches("^(>=|<=|>|<)\\s*\\d{1,3}$")) {
                int n = Integer.parseInt(s.replaceAll("[^0-9]",""));
                if (s.startsWith(">=")) return new RiskPredicate(v -> v >= n);
                if (s.startsWith("<=")) return new RiskPredicate(v -> v <= n);
                if (s.startsWith(">"))  return new RiskPredicate(v -> v >  n);
                if (s.startsWith("<"))  return new RiskPredicate(v -> v <  n);
            }
            if (s.matches("^\\d{1,3}\\s*-\\s*\\d{1,3}$")) {
                String[] ab = s.split("-");
                int a = Integer.parseInt(ab[0].trim());
                int b = Integer.parseInt(ab[1].trim());
                int lo = Math.min(a,b), hi = Math.max(a,b);
                return new RiskPredicate(v -> v >= lo && v <= hi);
            }
            if (s.matches("^\\d{1,3}$")) {
                int n = Integer.parseInt(s);
                return new RiskPredicate(v -> v == n);
            }
            String needle = s;
            return new RiskPredicate(v -> String.valueOf(v).contains(needle));
        }
    }

    private void installRiskValidation() {
        if (tfRisk == null) return;
        applyRiskValidation(tfRisk.getText());
        tfRisk.textProperty().addListener((o, ov, nv) -> applyRiskValidation(nv));
        if (tfRisk.getTooltip() == null) {
            tfRisk.setTooltip(new Tooltip("숫자(0-100), 비교(>=,<=,<,>,=), 범위(예: 25-80)"));
        }
    }
    private void applyRiskValidation(String txt) {
        Validation v = validateRiskSyntax(txt);
        if (!v.ok) {
            tfRisk.setStyle("-fx-border-color: #e53935; -fx-border-width: 1;");
            if (tfRisk.getTooltip() == null) tfRisk.setTooltip(new Tooltip(v.msg));
            else tfRisk.getTooltip().setText(v.msg);
        } else {
            tfRisk.setStyle(null);
            if (tfRisk.getTooltip() != null) {
                tfRisk.getTooltip().setText("숫자(0-100), 비교(>=,<=,<,>,=), 범위(예: 25-80)");
            }
        }
    }
    /** 빈 문자열=OK. 숫자/비교/범위만 허용, 값은 0~100. */
    private Validation validateRiskSyntax(String raw) {
        if (raw == null) return Validation.ok();
        String s = raw.trim();
        if (s.isEmpty()) return Validation.ok();

        var mRange = java.util.regex.Pattern.compile("^(\\d{1,3})\\s*-\\s*(\\d{1,3})$").matcher(s);
        if (mRange.matches()) {
            int a = Integer.parseInt(mRange.group(1));
            int b = Integer.parseInt(mRange.group(2));
            if (a > b)   return Validation.err("범위가 뒤바뀜: 최소 ≤ 최대");
            if (!in01(a) || !in01(b)) return Validation.err("0~100 사이 값만 허용");
            return Validation.ok();
        }

        var mCmp = java.util.regex.Pattern.compile("^(>=|<=|>|<|=)\\s*(\\d{1,3})$").matcher(s);
        if (mCmp.matches()) {
            int v = Integer.parseInt(mCmp.group(2));
            if (!in01(v)) return Validation.err("0~100 사이 값만 허용");
            return Validation.ok();
        }

        var mInt = java.util.regex.Pattern.compile("^(\\d{1,3})$").matcher(s);
        if (mInt.matches()) {
            int v = Integer.parseInt(mInt.group(1));
            if (!in01(v)) return Validation.err("0~100 사이 값만 허용");
            return Validation.ok();
        }

        return Validation.err("형식 오류: 숫자 / 비교(>=,<=,<,>,=) / 범위(예: 25-80)");
    }
    private static boolean in01(int v){ return v >= 0 && v <= 100; }
    private static final class Validation {
        final boolean ok; final String msg;
        private Validation(boolean ok, String msg){ this.ok = ok; this.msg = msg; }
        static Validation ok(){ return new Validation(true, ""); }
        static Validation err(String m){ return new Validation(false, m); }
    }

    // ====== (선택) 레거시 수동 JSON Export/Apply ======
    public String exportStateJson() {
        var typeSnap = new ArrayList<>(types);
        var sevSnap  = new ArrayList<>(severities);
        var m        = mode.get();
        var url      = opt(urlQ.get());
        var evi      = opt(eviQ.get());
        var risk     = opt(riskExpr.get());
        var fromStr  = (from.get()==null? "" : from.get().toString());
        var toStr    = (to.get()==null? "" : to.get().toString());

        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        sb.append("\"types\":").append(jsonArray(typeSnap)).append(',');
        sb.append("\"severities\":").append(jsonArray(mapSeverityNames(sevSnap))).append(',');
        sb.append("\"mode\":\"").append(escapeJson(m.name())).append("\",");
        sb.append("\"url\":\"").append(escapeJson(url)).append("\",");
        sb.append("\"evi\":\"").append(escapeJson(evi)).append("\",");
        sb.append("\"risk\":\"").append(escapeJson(risk)).append("\",");
        sb.append("\"from\":\"").append(escapeJson(fromStr)).append("\",");
        sb.append("\"to\":\"").append(escapeJson(toStr)).append("\"");
        sb.append('}');
        return sb.toString();
    }
    public void applyStateJson(String json) {
        if (json == null || json.isBlank()) return;
        loadingPrefs = true;
        try {
            types.clear();
            severities.clear();
            tfUrl.clear(); tfEvi.clear(); tfRisk.clear();
            dpFrom.setValue(null); dpTo.setValue(null);
            btnAnd.setSelected(true); mode.set(BoolMode.AND);

            Set<String> t = readArray(json, "types");
            Set<String> s = readArray(json, "severities");
            String m  = readString(json, "mode").orElse("AND");
            String url= readString(json, "url").orElse("");
            String evi= readString(json, "evi").orElse("");
            String r  = readString(json, "risk").orElse("");
            String f  = readString(json, "from").orElse("");
            String tt = readString(json, "to").orElse("");

            types.addAll(t);
            for (String sv : s) {
                try { severities.add(Severity.valueOf(sv)); } catch (Exception ignore) {}
            }
            if ("OR".equalsIgnoreCase(m)) { btnOr.setSelected(true); mode.set(BoolMode.OR); }
            else { btnAnd.setSelected(true); mode.set(BoolMode.AND); }

            urlQ.set(url);
            eviQ.set(evi);
            riskExpr.set(r);
            from.set(parseDate(f));
            to.set(parseDate(tt));

            applyChecksFromSet(typeMenu, name -> types.contains(name));
            applyChecksFromSet(sevMenu,  name -> {
                try { return severities.contains(Severity.valueOf(name)); }
                catch (Exception e) { return false; }
            });
        } finally {
            loadingPrefs = false;
            publish();
        }
    }
    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length()+16);
        for (int i=0;i<s.length();i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"'  -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }
    private static String jsonArray(Collection<String> vals) {
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        boolean first = true;
        for (String v : vals) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(escapeJson(v)).append('"');
        }
        sb.append(']');
        return sb.toString();
    }
    private static Optional<String> readString(String json, String key) {
        int k = json.indexOf(keyQuote(key));
        if (k < 0) return Optional.empty();
        int colon = json.indexOf(':', k);
        if (colon < 0) return Optional.empty();
        int firstQ = json.indexOf('"', colon);
        if (firstQ < 0) return Optional.empty();
        int end = firstQ + 1;
        StringBuilder sb = new StringBuilder();
        boolean esc = false;
        for (; end < json.length(); end++) {
            char ch = json.charAt(end);
            if (esc) {
                switch (ch) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case '"' -> sb.append('"');
                    case '\\'-> sb.append('\\');
                    default  -> sb.append(ch);
                }
                esc = false;
            } else if (ch == '\\') {
                esc = true;
            } else if (ch == '"') {
                break;
            } else {
                sb.append(ch);
            }
        }
        return Optional.of(sb.toString());
    }
    private static Set<String> readArray(String json, String key) {
        int k = json.indexOf(keyQuote(key));
        if (k < 0) return Set.of();
        int colon = json.indexOf(':', k);
        int lb = json.indexOf('[', colon);
        int rb = json.indexOf(']', lb);
        if (colon < 0 || lb < 0 || rb < 0) return Set.of();
        String inner = json.substring(lb+1, rb).trim();
        if (inner.isEmpty()) return Set.of();
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < inner.length()) {
            int q1 = inner.indexOf('"', i);
            if (q1 < 0) break;
            int q2 = q1 + 1;
            boolean esc = false;
            StringBuilder sb = new StringBuilder();
            for (; q2 < inner.length(); q2++) {
                char ch = inner.charAt(q2);
                if (esc) {
                    switch (ch) {
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case '"' -> sb.append('"');
                        case '\\'-> sb.append('\\');
                        default  -> sb.append(ch);
                    }
                    esc = false;
                } else if (ch == '\\') {
                    esc = true;
                } else if (ch == '"') {
                    break;
                } else {
                    sb.append(ch);
                }
            }
            out.add(sb.toString());
            i = q2 + 1;
            int comma = inner.indexOf(',', i);
            if (comma < 0) i = inner.length(); else i = comma + 1;
        }
        return new LinkedHashSet<>(out);
    }
    private static String keyQuote(String key) { return "\"" + key + "\""; }

    // ====== Micro-UX: Debounce helpers ======  (★ 추가)
    private void installDebounce() {
        // TextField 들: 타이핑 멈춘 뒤 150ms 후 publish()
        onTextChange(tfUrl,  this::publish);
        onTextChange(tfEvi,  this::publish);
        onTextChange(tfRisk, this::publish);

        // DatePicker 들: 값 변경 후 150ms 후 publish()
        valueChangeWithDebounce(dpFrom);
        valueChangeWithDebounce(dpTo);

        // MenuButton (type/severity): 메뉴 닫힐 때 한 번 정리 반영
        valueChangeWithDebounce(typeMenu);
        valueChangeWithDebounce(sevMenu);
    }

    private void onTextChange(TextField tf, Runnable onStableChange) {
        var timer = new PauseTransition(DEBOUNCE);
        timer.setOnFinished(e -> onStableChange.run());
        debounceMap.put(tf, timer);

        tf.textProperty().addListener((obs, o, n) -> {
            timer.stop(); timer.playFromStart();
        });
        // 포커스 잃으면 즉시 반영(선택)
        tf.focusedProperty().addListener((obs, o, focused) -> {
            if (!focused) { timer.stop(); onStableChange.run(); }
        });
    }

    private void valueChangeWithDebounce(Node node) {
        var timer = debounceMap.computeIfAbsent(node, k -> {
            var t = new PauseTransition(DEBOUNCE);
            t.setOnFinished(e -> publish());
            return t;
        });

        if (node == dpFrom) {
            dpFrom.valueProperty().addListener((o, ov, nv) -> { timer.stop(); timer.playFromStart(); });
            return;
        }
        if (node == dpTo) {
            dpTo.valueProperty().addListener((o, ov, nv) -> { timer.stop(); timer.playFromStart(); });
            return;
        }

        if (node instanceof MenuButton mb) {
            // 체크 변경은 즉시 SetChangeListener로도 반영되지만
            // 메뉴 닫힐 때 최종 상태로 한 번 더 안정화
            mb.showingProperty().addListener((o, was, showing) -> {
                if (!showing) { timer.stop(); timer.playFromStart(); }
            });
        }
    }

    // ====== Micro-UX: Fade-in for chips ======  (★ 추가)
    private void fadeIn(Node n) {
        n.setOpacity(0);
        FadeTransition ft = new FadeTransition(Duration.millis(120), n);
        ft.setFromValue(0);
        ft.setToValue(1);
        ft.play();
    }
}
