package com.webkillerai.app.ui;

import com.webkillerai.app.logging.LogSetup;
import com.webkillerai.core.model.Mode;            // ★ 변경: 최상위 Mode 사용
import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.Severity;
import com.webkillerai.core.model.VulnResult;
import com.webkillerai.core.service.ScanService;
import com.webkillerai.core.service.export.ExportCoordinator;
import com.webkillerai.core.service.export.OpenHtmlToPdfSupport;
import com.webkillerai.core.service.export.PdfReportExporter;
import com.webkillerai.core.util.ProgressListener;

import javafx.application.Platform;
import javafx.beans.binding.Bindings;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.TableColumnBase;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import java.util.prefs.Preferences;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class MainController {

    private static final Logger LOG = Logger.getLogger(MainController.class.getName());

    // ===== FXML refs =====
    @FXML private TextField targetField;
    @FXML private Spinner<Integer> depthSpinner;
    @FXML private Button scanButton;
    @FXML private ProgressBar progressBar;
    @FXML private Label statusLabel;

    @FXML private TableView<VulnResultView> issuesTable;
    @FXML private TableColumn<VulnResultView, String> colUrl, colType, colSeverity, colEvidence, colDetectedAt;

    @FXML private TextField pathField;
    @FXML private Button copyPathButton, openFolderButton;

    // 간단 필터/정렬 + Open report
    @FXML private TextField searchField;
    @FXML private CheckBox chkHigh, chkMed, chkLow;
    @FXML private ToggleButton tglSeverityDesc;
    @FXML private Button openReportButton;

    // 고급 필터 & 프리셋
    @FXML private AdvancedFilterBar filterBar;
    @FXML private ComboBox<String> cbPreset;
    @FXML private Button btnApplyPreset, btnSavePreset, btnDeletePreset;

    // 포맷 & 출력 폴더
    @FXML private CheckBox chkExportJson;
    @FXML private CheckBox chkExportPdf;
    @FXML private TextField outputDirField;

    // ETA/취소
    @FXML private Label etaLabel;
    @FXML private Button cancelBtn;

    // 로그 레벨 토글
    @FXML private ComboBox<String> cbLogLevel;

    // ★ 모드/RPS/동시성/스코프/리다이렉트/Evidence 토글 (있으면 사용, 없으면 기본값)
    @FXML private ComboBox<Mode> modeCombo;                 // ★ 변경
    @FXML private Spinner<Integer> rpsSpinner;
    @FXML private Spinner<Integer> ccSpinner;
    @FXML private CheckBox sameDomainCheck;
    @FXML private CheckBox followRedirectsCheck;
    @FXML private CheckBox showEvidenceCheck;

    // ===== prefs keys =====
    private static final String PREF_EXPORT_JSON = "export_json";
    private static final String PREF_EXPORT_PDF  = "export_pdf";
    private static final String PREF_OUT_DIR     = "out_dir";

    // ===== Preset 저장소 (Preferences) =====
    private static final String PRESET_NODE = "/com/webkillerai/app/presets";
    private final Preferences presetPrefs = Preferences.userRoot().node(PRESET_NODE);
    private final ObservableList<String> presetNames = FXCollections.observableArrayList();

    // ===== table model =====
    private final ObservableList<VulnResultView> items = FXCollections.observableArrayList();
    private final FilteredList<VulnResultView> filtered = new FilteredList<>(items, it -> true);
    private final SortedList<VulnResultView>   sorted   = new SortedList<>(filtered);

    // 도메인 ↔ 뷰 매핑 & 필터 결합 상태
    private final Map<VulnResultView, VulnResult> viewToDomain = new IdentityHashMap<>();
    private Predicate<VulnResultView> quickFilterPred = v -> true; // 간단 필터
    private Predicate<VulnResultView> advFilterPred   = v -> true; // 고급 필터

    // ===== state =====
    private Task<List<VulnResult>> currentTask;
    private final AtomicBoolean cancelFlag = new AtomicBoolean(false);

    @FXML
    private void initialize() {
        // Depth
        if (depthSpinner != null) {
            depthSpinner.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(0, 12, 2));
        }

        // 모드/성능/스코프/증거 토글
        if (modeCombo != null) {
            modeCombo.getItems().setAll(Mode.values());                   // ★ 변경
            modeCombo.getSelectionModel().select(Mode.SAFE);              // ★ 변경
        }
        if (rpsSpinner != null) {
            rpsSpinner.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 1000, 7));
        }
        if (ccSpinner != null) {
            ccSpinner.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 256, 2));
        }
        if (sameDomainCheck != null) sameDomainCheck.setSelected(true);
        if (followRedirectsCheck != null) followRedirectsCheck.setSelected(true);
        if (showEvidenceCheck != null) {
            showEvidenceCheck.setSelected(modeCombo != null && modeCombo.getValue() == Mode.SAFE_PLUS); // ★ 변경
            if (modeCombo != null) {
                modeCombo.valueProperty().addListener((o, ov, nv) -> {
                    if (nv == Mode.SAFE_PLUS && !showEvidenceCheck.isSelected()) {                      // ★ 변경
                        showEvidenceCheck.setSelected(true);
                    } else if (nv == Mode.SAFE && showEvidenceCheck.isSelected()) {                     // ★ 변경
                        showEvidenceCheck.setSelected(false);
                    }
                });
            }
        }

        // 테이블 바인딩
        if (issuesTable != null) {
            if (colUrl != null)        colUrl.setCellValueFactory(c -> c.getValue().urlProperty());
            if (colType != null)       colType.setCellValueFactory(c -> c.getValue().typeProperty());
            if (colSeverity != null)   colSeverity.setCellValueFactory(c -> c.getValue().severityProperty());
            if (colEvidence != null)   colEvidence.setCellValueFactory(c -> c.getValue().evidenceProperty());
            if (colDetectedAt != null) colDetectedAt.setCellValueFactory(c -> c.getValue().detectedAtProperty());

            addTooltipCellFactory(colUrl);
            addTooltipCellFactory(colEvidence);
            addTooltipCellFactory(colDetectedAt);

            issuesTable.setItems(sorted);
            issuesTable.comparatorProperty().addListener((obs, old, neu) -> applySort());

            issuesTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
            setupCopyShortcuts();

            issuesTable.setRowFactory(tv -> {
                TableRow<VulnResultView> row = new TableRow<>();
                row.setOnMouseClicked(e -> {
                    if (e.getClickCount() == 2 && !row.isEmpty()) {
                        var v = row.getItem();
                        if (v != null && v.getUrl() != null && !v.getUrl().isBlank()) {
                            openUrlOrNothing(v.getUrl());
                        }
                    }
                });

                ContextMenu cm = new ContextMenu();
                MenuItem miOpen   = new MenuItem("Open URL");
                MenuItem miCopyU  = new MenuItem("Copy URL");
                MenuItem miCopyE  = new MenuItem("Copy Evidence");
                MenuItem miCopyJ  = new MenuItem("Copy row as JSON");
                MenuItem miCopyC  = new MenuItem("Copy row as CSV");
                MenuItem miSelCsv  = new MenuItem("Copy selected rows (CSV)");
                MenuItem miSelJson = new MenuItem("Copy selected rows (JSON)");

                miOpen.setOnAction(e -> { var v = row.getItem(); if (v != null) openUrlOrNothing(v.getUrl()); });
                miCopyU.setOnAction(e -> { var v = row.getItem(); if (v != null) copyToClipboard(nullToEmpty(v.getUrl())); });
                miCopyE.setOnAction(e -> { var v = row.getItem(); if (v != null) copyToClipboard(nullToEmpty(v.getEvidence())); });
                miCopyJ.setOnAction(e -> { var v = row.getItem(); if (v != null) copyToClipboard(rowAsJson(v)); });
                miCopyC.setOnAction(e -> { var v = row.getItem(); if (v != null) copyToClipboard(rowAsCsv(v)); });
                miSelCsv.setOnAction(e -> copySelectedAsCsv(true));
                miSelJson.setOnAction(e -> copySelectedAsJson());

                cm.getItems().addAll(
                        miOpen,
                        new SeparatorMenuItem(),
                        miCopyU, miCopyE,
                        new SeparatorMenuItem(),
                        miCopyJ, miCopyC,
                        new SeparatorMenuItem(),
                        miSelCsv, miSelJson
                );

                var rowOnly = List.of(miOpen, miCopyU, miCopyE, miCopyJ, miCopyC);
                row.itemProperty().addListener((o, ov, nv) -> {
                    boolean disabled = (nv == null);
                    rowOnly.forEach(it -> it.setDisable(disabled));
                });

                row.setContextMenu(cm);
                return row;
            });
        }

        // 검색/필터/정렬 리스너
        if (searchField != null)    searchField.textProperty().addListener((o,ov,nv)->applyFilters());
        if (chkHigh != null)        chkHigh.selectedProperty().addListener((o,ov,nv)->applyFilters());
        if (chkMed != null)         chkMed.selectedProperty().addListener((o,ov,nv)->applyFilters());
        if (chkLow != null)         chkLow.selectedProperty().addListener((o,ov,nv)->applyFilters());
        if (tglSeverityDesc != null)tglSeverityDesc.selectedProperty().addListener((o,ov,nv)->applySort());

        // Prefs
        Preferences prefs = Preferences.userNodeForPackage(MainController.class);

        // JSON 동시 저장
        if (chkExportJson != null) {
            chkExportJson.setSelected(prefs.getBoolean(PREF_EXPORT_JSON, true));
            chkExportJson.selectedProperty().addListener((o,ov,nv) ->
                    prefs.putBoolean(PREF_EXPORT_JSON, Boolean.TRUE.equals(nv)));
        }

        // PDF 저장(가용성 확인)
        if (chkExportPdf != null) {
            boolean defPdf = Boolean.parseBoolean(System.getProperty("wk.export.pdf", "false"));
            boolean savedPdf = prefs.getBoolean(PREF_EXPORT_PDF, defPdf);
            chkExportPdf.setSelected(savedPdf);
            chkExportPdf.selectedProperty().addListener((o,ov,nv) ->
                    prefs.putBoolean(PREF_EXPORT_PDF, Boolean.TRUE.equals(nv)));

            boolean pdfAvail = false;
            try {
                pdfAvail = OpenHtmlToPdfSupport.isAvailable() || PdfReportExporter.isAvailable();
            } catch (Throwable ignore) {}

            if (!pdfAvail) {
                chkExportPdf.setDisable(true);
                chkExportPdf.setTooltip(new Tooltip("PDF renderer not available (openhtmltopdf/renderer 미탑재)"));
            }
        }

        // 출력 폴더
        if (outputDirField != null) {
            String saved = prefs.get(PREF_OUT_DIR, "out");
            outputDirField.setText(saved);
            outputDirField.textProperty().addListener((o, ov, nv) -> {
                if (nv != null && !nv.isBlank()) prefs.put(PREF_OUT_DIR, nv.trim());
            });
        }

        // AdvancedFilterBar → Predicate<VulnResult>를 받아 View로 래핑
        if (filterBar != null) {
            filterBar.setPredicateSink((Predicate<VulnResult> domainPred) -> {
                advFilterPred = (vm) -> {
                    VulnResult d = viewToDomain.get(vm);
                    return d != null && domainPred.test(d);
                };
                recomputeFilters();
            });
        }

        // 프리셋 콤보/버튼 연결
        if (cbPreset != null) {
            cbPreset.setItems(presetNames);
            reloadPresetList();
        }
        if (btnApplyPreset != null)  btnApplyPreset.setOnAction(e -> onApplyPreset());
        if (btnSavePreset != null)   btnSavePreset.setOnAction(e -> onSavePreset());
        if (btnDeletePreset != null) btnDeletePreset.setOnAction(e -> onDeletePreset());

        // 로그 레벨 콤보
        initLogLevelToggle();

        // 초기 적용
        applyFilters();
        applySort();

        // 버튼 상태 바인딩
        if (copyPathButton != null && pathField != null) {
            copyPathButton.disableProperty().bind(
                    Bindings.createBooleanBinding(
                            () -> pathField.getText() == null || pathField.getText().isBlank(),
                            pathField.textProperty()));
        }
        if (openFolderButton != null && copyPathButton != null) {
            openFolderButton.disableProperty().bind(copyPathButton.disableProperty());
        }
        if (openReportButton != null && copyPathButton != null) {
            openReportButton.disableProperty().bind(copyPathButton.disableProperty());
        }

        // ETA/취소 초기
        if (etaLabel != null) etaLabel.setText("ETA --:--");
        if (cancelBtn != null) cancelBtn.setDisable(true);

        // 단축키(Enter, ESC, Ctrl+F)
        Platform.runLater(() -> {
            if (scanButton != null && scanButton.getScene() != null) {
                var scene = scanButton.getScene();
                scene.getAccelerators().put(new KeyCodeCombination(KeyCode.ENTER),
                        () -> { if (!scanButton.isDisabled()) onScan(); });
                scene.getAccelerators().put(new KeyCodeCombination(KeyCode.ESCAPE),
                        this::onCancelScan);
                scene.getAccelerators().put(new KeyCodeCombination(KeyCode.F, KeyCombination.CONTROL_DOWN),
                        () -> { if (searchField != null) searchField.requestFocus(); });
            }
        });
    }

    // =========================
    // 프리셋: 저장/적용/삭제
    // =========================

    private void reloadPresetList() {
        try {
            String[] keys = presetPrefs.keys(); // 각 key가 preset name
            Arrays.sort(keys, String.CASE_INSENSITIVE_ORDER);
            presetNames.setAll(keys);
        } catch (Exception e) {
            presetNames.clear();
        }
    }

    private void onSavePreset() {
        if (filterBar == null) return;
        TextInputDialog d = new TextInputDialog();
        d.setTitle("Save Filter Preset");
        d.setHeaderText("Preset name");
        d.setContentText("Name:");
        d.showAndWait().ifPresent(name -> {
            String trimmed = name == null ? "" : name.trim();
            if (trimmed.isEmpty()) return;
            String json = filterBar.exportStateJson();
            presetPrefs.put(trimmed, json);
            reloadPresetList();
            if (cbPreset != null) cbPreset.getSelectionModel().select(trimmed);
        });
    }

    private void onApplyPreset() {
        if (filterBar == null || cbPreset == null) return;
        String name = cbPreset.getValue();
        if (name == null || name.isBlank()) return;
        String json = presetPrefs.get(name, null);
        if (json != null) filterBar.applyStateJson(json);
    }

    private void onDeletePreset() {
        if (cbPreset == null) return;
        String name = cbPreset.getValue();
        if (name == null || name.isBlank()) return;
        presetPrefs.remove(name);
        reloadPresetList();
        cbPreset.getSelectionModel().clearSelection();
    }

    // =========================
    // UI Handlers
    // =========================

    @FXML
    private void onScan() {
        String target = Optional.ofNullable(targetField).map(TextField::getText).orElse("");
        int depth = Optional.ofNullable(depthSpinner).map(s -> {
            Integer v = s.getValue();
            return (v == null ? 2 : v);
        }).orElse(2);

        if (target.isBlank()) {
            alert("Target URL을 입력하세요.");
            return;
        }

        LOG.info(() -> "Scan requested: target=" + target + ", depth=" + depth);

        // YAML 로더 미사용: UI 값만 사용
        ScanConfig cfg = new ScanConfig();
        cfg.setTarget(target);
        cfg.setMaxDepth(depth);

        // 모드/RPS/동시성/스코프/리다이렉트
        Mode mode = (modeCombo != null && modeCombo.getValue() != null)    // ★ 변경
                ? modeCombo.getValue() : Mode.SAFE;                        // ★ 변경
        cfg.setMode(mode);                                                 // ★ 변경

        int rps = (rpsSpinner != null && rpsSpinner.getValue() != null) ? rpsSpinner.getValue() : 7;
        cfg.setRps(Math.max(1, rps));

        int cc  = (ccSpinner  != null && ccSpinner.getValue()  != null) ? ccSpinner.getValue() : 2;
        cfg.setConcurrency(Math.max(1, cc));

        boolean sameDomain = sameDomainCheck == null || sameDomainCheck.isSelected();
        cfg.setSameDomainOnly(sameDomain);

        boolean follow = followRedirectsCheck == null || followRedirectsCheck.isSelected();
        cfg.setFollowRedirects(follow);

        // Evidence 표시 토글 → 시스템 프로퍼티로 Exporter 제어
        boolean showEvi = (showEvidenceCheck != null)
                ? showEvidenceCheck.isSelected()
                : (mode == Mode.SAFE_PLUS);                                // ★ 변경
        System.setProperty("wk.report.showEvidenceDetails", showEvi ? "on" : "off");

        runScan(cfg);
    }

    @FXML
    private void onBrowseOutputDir() {
        try {
            DirectoryChooser dc = new DirectoryChooser();
            dc.setTitle("Select output folder");

            String cur = (outputDirField != null) ? outputDirField.getText().trim() : "";
            if (!cur.isBlank()) {
                Path p = Path.of(cur);
                if (Files.isDirectory(p)) dc.setInitialDirectory(p.toFile());
            }

            var owner = (scanButton != null && scanButton.getScene() != null)
                    ? scanButton.getScene().getWindow() : null;
            var chosen = dc.showDialog(owner);
            if (chosen != null && outputDirField != null) {
                outputDirField.setText(chosen.getAbsolutePath());
            }
        } catch (Exception e) {
            alert("폴더 선택 실패: " + e.getMessage());
        }
    }

    @FXML
    private void onCopyPath() {
        if (pathField == null || pathField.getText().isBlank()) return;
        ClipboardContent cc = new ClipboardContent();
        cc.putString(pathField.getText());
        Clipboard.getSystemClipboard().setContent(cc);
        statusLabel.setText("Path copied.");
    }

    @FXML
    private void onOpenFolder() {
        if (pathField == null || pathField.getText().isBlank()) return;
        try {
            Path p = Path.of(pathField.getText());
            Path dir = (p.getParent() != null) ? p.getParent() : p;
            if (!Files.exists(dir)) {
                alert("폴더가 존재하지 않습니다: " + dir);
                return;
            }
            LOG.info(() -> "Open folder: " + dir);
            openWithOS(dir);
        } catch (IOException e) {
            alert("폴더 열기 실패: " + e.getMessage());
        }
    }

    @FXML
    private void onOpenReport() {
        if (pathField == null || pathField.getText().isBlank()) {
            alert("열 수 있는 최근 보고서가 없습니다. 스캔 후 다시 시도하세요.");
            return;
        }
        try {
            Path p = Path.of(pathField.getText());
            if (!Files.exists(p)) {
                alert("파일이 존재하지 않습니다: " + p);
                return;
            }
            Path toOpen = preferHtml(p).orElse(p);
            LOG.info(() -> "Open report: " + toOpen);
            openWithOS(toOpen);
        } catch (IOException e) {
            alert("보고서 열기 실패: " + e.getMessage());
        }
    }

    @FXML
    private void onCancelScan() {
        cancelFlag.set(true);
        if (currentTask != null && currentTask.isRunning()) {
            currentTask.cancel(true);
            if (cancelBtn != null) cancelBtn.setDisable(true);
            if (etaLabel != null) etaLabel.setText("취소 요청됨");
            LOG.warning("Scan cancelled by user.");
        }
    }

    @FXML
    private void onExportCsv() {
        if (issuesTable == null || issuesTable.getItems() == null) return;
        var fc = new FileChooser();
        fc.setTitle("CSV로 내보내기");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV", "*.csv"));
        fc.setInitialFileName("issues-" + java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmm")) + ".csv");

        var file = fc.showSaveDialog(issuesTable.getScene().getWindow());
        if (file == null) return;

        try {
            exportTableToCsv(issuesTable, Path.of(file.toURI()));
            statusLabel.setText("CSV saved: " + file.getName());
        } catch (Exception e) {
            e.printStackTrace();
            alert("CSV 저장 실패: " + e.getMessage());
        }
    }

    // =========================
    // 스캔 실행 (ProgressListener/취소 연동)
    // =========================

    private void runScan(ScanConfig cfg) {
        final String startedIso = Instant.now().toString();
        final ScanService svc = new ScanService(cfg);

        cancelFlag.set(false);
        if (cancelBtn != null) cancelBtn.setDisable(false);
        if (etaLabel != null) etaLabel.setText("ETA 계산중");

        LOG.info(() -> "Scan starting: target=" + cfg.getTarget() + ", maxDepth=" + cfg.getMaxDepth()
                + ", mode=" + cfg.getMode() + ", rps=" + cfg.getRps() + ", cc=" + cfg.getConcurrency());

        currentTask = new Task<>() {
            @Override
            protected List<VulnResult> call() {
                updateMessage("Scanning " + cfg.getTarget());
                updateProgress(-1, 1);
                final long startMs = System.currentTimeMillis();

                ProgressListener pl = (p, phase, done, total) -> {
                    if (isCancelled() || cancelFlag.get()) return;

                    if (total > 0) {
                        updateProgress(done, total);
                    } else if (p > 0.0) {
                        updateProgress((long)Math.round(p * 100), 100);
                    } else {
                        updateProgress(-1, 1);
                    }

                    String msg;
                    if (p > 0.0) {
                        long elapsed = System.currentTimeMillis() - startMs;
                        long remain  = (long)(elapsed * (1.0 - p) / Math.max(p, 1e-6));
                        String eta   = String.format("%d:%02d", remain/60000L, (remain%60000L)/1000L);
                        msg = phase + " · ETA " + eta;
                        if (etaLabel != null) Platform.runLater(() -> etaLabel.setText("ETA " + eta));
                    } else {
                        msg = phase + " · 계산중";
                        if (etaLabel != null) Platform.runLater(() -> etaLabel.setText("ETA --:--"));
                    }
                    updateMessage(msg);
                };

                List<VulnResult> out = svc.run(pl, cancelFlag);

                updateProgress(1, 1);
                updateMessage("Scan finished");
                return out;
            }
        };

        progressBar.progressProperty().bind(currentTask.progressProperty());
        statusLabel.textProperty().bind(currentTask.messageProperty());
        scanButton.setDisable(true);

        currentTask.setOnSucceeded(ev -> {
            List<VulnResult> results = currentTask.getValue();
            LOG.info(() -> "Scan finished: results=" + (results != null ? results.size() : 0));

            // 뷰 ↔ 도메인 매핑 및 Items 채우기
            viewToDomain.clear();
            var vms = new ArrayList<VulnResultView>(results.size());
            for (VulnResult r : results) {
                VulnResultView v = VulnResultView.from(r);
                vms.add(v);
                viewToDomain.put(v, r);
            }
            items.setAll(vms);

            // 필터/정렬 재적용
            applyFilters();
            applySort();

            try {
                // Save to 경로
                Path outRoot;
                String uiDir = (outputDirField != null && outputDirField.getText() != null)
                        ? outputDirField.getText().trim() : "";
                outRoot = !uiDir.isBlank() ? Path.of(uiDir) : resolveOutDir(cfg);
                try { Files.createDirectories(outRoot); } catch (IOException ignore) {}

                // 포맷 결정
                Set<String> formats = selectedFormats(cfg);
                if (LOG.isLoggable(Level.FINE)) LOG.fine("selectedFormats=" + formats);

                var coordinator = new ExportCoordinator()
                        .withRuntime(svc)
                        .withAlsoJsonToggle(chkExportJson != null ? chkExportJson.isSelected() : null);

                Path last = coordinator.exportAll(outRoot, cfg, results, startedIso, formats);

                if (last != null) {
                    LOG.info(() -> "Report exported: " + last);
                }
                if (pathField != null && last != null) pathField.setText(last.toString());

            } catch (Exception e) {
                alert("Export 실패: " + e.getMessage());
                LOG.log(Level.SEVERE, "Export failed", e);
            }

            // UI 정리
            progressBar.progressProperty().unbind();
            statusLabel.textProperty().unbind();
            statusLabel.setText("Done.");
            scanButton.setDisable(false);
            if (cancelBtn != null) cancelBtn.setDisable(true);
            if (etaLabel != null) etaLabel.setText("완료");
        });

        currentTask.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            statusLabel.textProperty().unbind();
            scanButton.setDisable(false);
            if (cancelBtn != null) cancelBtn.setDisable(true);

            Throwable ex = currentTask.getException();
            LOG.log(Level.SEVERE, "Scan failed", ex);
            alert("Scan 실패: " + (ex != null ? ex.getMessage() : "Unknown error"));
            if (etaLabel != null) etaLabel.setText("오류");
        });

        currentTask.setOnCancelled(ev -> {
            progressBar.progressProperty().unbind();
            statusLabel.textProperty().unbind();
            scanButton.setDisable(false);
            if (cancelBtn != null) cancelBtn.setDisable(true);
            statusLabel.setText("취소됨");
            if (etaLabel != null) etaLabel.setText("취소됨");
            LOG.warning("Scan task cancelled.");
        });

        Thread t = new Thread(currentTask, "scan-task");
        t.setDaemon(true);
        t.start();
    }

    // =========================
    // 파일/URL 열기 & 선택 유틸
    // =========================

    private Optional<Path> preferHtml(Path current) throws IOException {
        String name = current.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".html")) return Optional.of(current);
        if (name.endsWith(".json")) {
            Path htmlSibling = current.resolveSibling(
                    current.getFileName().toString().replaceFirst("\\.json$", ".html"));
            if (Files.exists(htmlSibling)) return Optional.of(htmlSibling);
            return newestHtml(current.getParent());
        }
        return newestHtml(current.getParent());
    }

    private Optional<Path> newestHtml(Path dir) throws IOException {
        if (dir == null || !Files.isDirectory(dir)) return Optional.empty();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "scan-*.html")) {
            Path newest = null;
            long latest = Long.MIN_VALUE;
            for (Path p : ds) {
                long m = Files.getLastModifiedTime(p).toMillis();
                if (m > latest) { latest = m; newest = p; }
            }
            return Optional.ofNullable(newest);
        }
    }

    private void openWithOS(Path p) throws IOException {
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().open(p.toFile());
            return;
        }
        String os = System.getProperty("os.name", "generic").toLowerCase(Locale.ROOT);
        ProcessBuilder pb;
        if (os.contains("mac")) {
            pb = new ProcessBuilder("open", p.toString());
        } else if (os.contains("win")) {
            pb = new ProcessBuilder("explorer.exe", p.toString());
        } else {
            pb = new ProcessBuilder("xdg-open", p.toString());
        }
        pb.start();
    }

    private void openUrlOrNothing(String url) {
        try {
            URI u = URI.create(url);
            if (Desktop.isDesktopSupported() && u.getScheme() != null && (u.getScheme().startsWith("http"))) {
                Desktop.getDesktop().browse(u);
            }
        } catch (Exception ignore) {
            // noop
        }
    }

    // =========================
    // 필터/정렬
    // =========================

    private void applyFilters() {
        String q = (searchField == null || searchField.getText() == null)
                ? "" : searchField.getText().trim().toLowerCase(Locale.ROOT);
        boolean high = chkHigh == null || chkHigh.isSelected();
        boolean med  = chkMed  == null || chkMed.isSelected();
        boolean low  = chkLow  == null || chkLow.isSelected();

        EnumSet<Severity> allowed = EnumSet.noneOf(Severity.class);
        if (high) allowed.add(Severity.HIGH);
        if (med)  allowed.add(Severity.MEDIUM);
        if (low)  allowed.add(Severity.LOW);

        quickFilterPred = v -> {
            Severity sv = normalizeForUi(severityOf(v.getSeverity()));
            if (sv != null && !allowed.contains(sv)) return false;
            if (q.isEmpty()) return true;
            return s(v.getUrl()).contains(q)
                    || s(v.getType()).contains(q)
                    || s(v.getEvidence()).contains(q)
                    || s(v.getDetectedAt()).contains(q);
        };

        recomputeFilters();
    }

    private void recomputeFilters() {
        filtered.setPredicate(v -> quickFilterPred.test(v) && advFilterPred.test(v));
    }

    private void applySort() {
        boolean desc = tglSeverityDesc == null || tglSeverityDesc.isSelected();
        Comparator<VulnResultView> sevCmp = (a, b) -> {
            int wa = sevWeight(normalizeForUi(severityOf(a.getSeverity())));
            int wb = sevWeight(normalizeForUi(severityOf(b.getSeverity())));
            return desc ? Integer.compare(wb, wa) : Integer.compare(wa, wb);
        };

        Comparator<VulnResultView> userCmp = (issuesTable != null) ? issuesTable.getComparator() : null;
        Comparator<VulnResultView> combined = (userCmp != null) ? sevCmp.thenComparing(userCmp) : sevCmp;
        sorted.setComparator(combined);
    }

    private static Severity normalizeForUi(Severity s){
        if (s == null) return null;
        return switch (s){
            case CRITICAL -> Severity.HIGH;
            case INFO     -> Severity.LOW;
            default       -> s;
        };
    }

    private static Severity severityOf(String s) {
        if (s == null) return null;
        try { return Severity.valueOf(s.trim().toUpperCase(Locale.ROOT)); }
        catch (Exception ignore) { return null; }
    }

    private static int sevWeight(Severity s) {
        if (s == null) return 0;
        return switch (s) {
            case HIGH -> 3; case MEDIUM -> 2; case LOW -> 1; default -> 0;
        };
    }

    private static String s(String x){ return x==null? "": x.toLowerCase(Locale.ROOT); }

    // =========================
    // 옵션 해석 유틸
    // =========================

    /** output.dir → 없으면 "out" (리플렉션 호환) */
    private static Path resolveOutDir(ScanConfig cfg) {
        Objects.requireNonNull(cfg, "cfg");
        try {
            Object out = cfg.getClass().getMethod("getOutput").invoke(cfg);
            if (out == null) return Path.of("out");
            Object dir = out.getClass().getMethod("getDir").invoke(out);
            if (dir instanceof String s && !s.isBlank()) return Path.of(s);
        } catch (Exception ignore) {}
        return Path.of("out");
    }

    /** output.format (예: "json,html,pdf") → 소문자 set. 기본 "json" */
    private static Set<String> resolveFormats(ScanConfig cfg) {
        try {
            Object out = cfg.getClass().getMethod("getOutput").invoke(cfg);
            if (out == null) return Set.of("json");
            Object fmt = out.getClass().getMethod("getFormat").invoke(out);
            if (fmt instanceof String s && !s.isBlank()) {
                String[] parts = s.split(",");
                Set<String> set = new LinkedHashSet<>();
                for (String p : parts) {
                    String v = p.trim().toLowerCase(Locale.ROOT);
                    if (!v.isEmpty()) set.add(v);
                }
                return set.isEmpty() ? Set.of("json") : set;
            }
        } catch (Exception ignore) {}
        return Set.of("json");
    }

    /** 최종 포맷 선택: HTML 기본 + (YAML의 PDF 유지) + JSON은 UI 토글 우선 + 시스템 강제 PDF */
    private Set<String> selectedFormats(ScanConfig cfg){
        Set<String> out = new LinkedHashSet<>();
        out.add("html");

        Set<String> byCfg = resolveFormats(cfg);
        if (byCfg.contains("pdf")) out.add("pdf");

        // UI 체크박스 우선
        if (chkExportPdf != null && chkExportPdf.isSelected()) out.add("pdf");

        // 시스템 프로퍼티로 강제
        if (Boolean.parseBoolean(System.getProperty("wk.export.pdf", "false"))) {
            out.add("pdf");
        }

        if (chkExportJson != null) {
            if (chkExportJson.isSelected()) out.add("json");
            return out;
        }

        if (byCfg.contains("json")) out.add("json");
        return out;
    }

    // =========================
    // CSV export helpers
    // =========================

    private static <T> void exportTableToCsv(TableView<T> table, Path path) throws IOException {
        try (var w = Files.newBufferedWriter(path, java.nio.charset.StandardCharsets.UTF_8)) {
            // 헤더
            String header = table.getColumns().stream()
                    .map(c -> Objects.toString(((TableColumnBase<?, ?>) c).getText(), ""))
                    .map(MainController::csvEscape)
                    .collect(java.util.stream.Collectors.joining(","));
            w.write(header); w.newLine();
            // 본문
            for (T item : table.getItems()) {
                java.util.List<String> cells = new java.util.ArrayList<>();
                for (Object c : table.getColumns()) {
                    @SuppressWarnings("unchecked")
                    TableColumn<T, ?> col = (TableColumn<T, ?>) c;
                    Object v = (col.getCellObservableValue(item) != null)
                            ? col.getCellObservableValue(item).getValue()
                            : "";
                    cells.add(csvEscape(Objects.toString(v, "")));
                }
                w.write(String.join(",", cells)); w.newLine();
            }
        }
    }

    private static String csvEscape(String s) {
        boolean need = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String body = s.replace("\"", "\"\"");
        return need ? "\"" + body + "\"" : body;
    }

    private static <S> void addTooltipCellFactory(TableColumn<S, String> col) {
        if (col == null) return;
        col.setCellFactory(c -> new TableCell<>() {
            @Override protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty ? null : item);
                setTooltip((!empty && item != null && !item.isBlank()) ? new Tooltip(item) : null);
            }
        });
    }

    // =========================
    // Alert
    // =========================

    private void alert(String msg) {
        Platform.runLater(() -> {
            Alert a = new Alert(Alert.AlertType.INFORMATION, msg, ButtonType.OK);
            a.setHeaderText(null);
            a.showAndWait();
        });
    }

    // =========================
    // 선택 복사 단축키/컨텍스트 메뉴 헬퍼
    // =========================

    private void setupCopyShortcuts() {
        if (issuesTable == null) return;
        issuesTable.setOnKeyPressed(e -> {
            if (e.isControlDown() && e.getCode() == KeyCode.C && !e.isShiftDown()) {
                copySelectedAsCsv(true); // Ctrl+C → CSV (헤더 포함)
                e.consume();
            } else if (e.isControlDown() && e.isShiftDown() && e.getCode() == KeyCode.C) {
                copySelectedAsJson();    // Ctrl+Shift+C → JSON 배열
                e.consume();
            }
        });
    }

    /** 선택된 행들을 CSV로 클립보드 복사. withHeader=true면 헤더 포함 */
    private void copySelectedAsCsv(boolean withHeader) {
        if (issuesTable == null) return;
        List<VulnResultView> sel = new ArrayList<>(issuesTable.getSelectionModel().getSelectedItems());
        if (sel.isEmpty()) {
            var focused = issuesTable.getFocusModel() != null ? issuesTable.getFocusModel().getFocusedItem() : null;
            if (focused != null) sel = List.of(focused);
        }
        if (sel.isEmpty()) return;

        StringBuilder sb = new StringBuilder();

        if (withHeader) {
            String header = issuesTable.getColumns().stream()
                    .map(c -> Objects.toString(((TableColumnBase<?, ?>) c).getText(), ""))
                    .map(MainController::csvEscape)
                    .collect(java.util.stream.Collectors.joining(","));
            sb.append(header).append("\n");
        }

        for (VulnResultView v : sel) {
            List<String> cells = new ArrayList<>();
            for (Object c : issuesTable.getColumns()) {
                @SuppressWarnings("unchecked")
                TableColumn<VulnResultView, ?> col = (TableColumn<VulnResultView, ?>) c;
                Object val = (col.getCellObservableValue(v) != null)
                        ? col.getCellObservableValue(v).getValue()
                        : "";
                cells.add(csvEscape(Objects.toString(val, "")));
            }
            sb.append(String.join(",", cells)).append("\n");
        }

        ClipboardContent cc = new ClipboardContent();
        cc.putString(sb.toString());
        Clipboard.getSystemClipboard().setContent(cc);
        if (statusLabel != null) statusLabel.setText("Copied " + sel.size() + " row(s) as CSV.");
    }

    /** 선택된 행들을 JSON 배열로 클립보드 복사 */
    private void copySelectedAsJson() {
        if (issuesTable == null) return;
        List<VulnResultView> sel = new ArrayList<>(issuesTable.getSelectionModel().getSelectedItems());
        if (sel.isEmpty()) {
            var focused = issuesTable.getFocusModel() != null ? issuesTable.getFocusModel().getFocusedItem() : null;
            if (focused != null) sel = List.of(focused);
        }
        if (sel.isEmpty()) return;

        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < sel.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(rowAsJson(sel.get(i)));
        }
        sb.append("]");

        ClipboardContent cc = new ClipboardContent();
        cc.putString(sb.toString());
        Clipboard.getSystemClipboard().setContent(cc);
        if (statusLabel != null) statusLabel.setText("Copied " + sel.size() + " row(s) as JSON.");
    }

    // =========================
    // Row copy helpers
    // =========================

    private static String nullToEmpty(String s){ return s == null ? "" : s; }

    private void copyToClipboard(String s) {
        if (s == null) return;
        ClipboardContent cc = new ClipboardContent();
        cc.putString(s);
        Clipboard.getSystemClipboard().setContent(cc);
        if (statusLabel != null) statusLabel.setText("Copied.");
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
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

    private String rowAsJson(VulnResultView v) {
        return "{"
                + "\"url\":\""        + jsonEscape(v.getUrl())        + "\","
                + "\"type\":\""       + jsonEscape(v.getType())       + "\","
                + "\"severity\":\""   + jsonEscape(v.getSeverity())   + "\","
                + "\"evidence\":\""   + jsonEscape(v.getEvidence())   + "\","
                + "\"detectedAt\":\"" + jsonEscape(v.getDetectedAt()) + "\""
                + "}";
    }

    private String rowAsCsv(VulnResultView v) {
        String[] cols = {
                nullToEmpty(v.getUrl()),
                nullToEmpty(v.getType()),
                nullToEmpty(v.getSeverity()),
                nullToEmpty(v.getEvidence()),
                nullToEmpty(v.getDetectedAt())
        };
        return String.join(",",
                Arrays.stream(cols).map(MainController::csvEscape).toArray(String[]::new));
    }

    // =========================
    // 로그 레벨 토글 초기화 (LogSetup 연동)
    // =========================
    private void initLogLevelToggle() {
        if (cbLogLevel == null) return;

        cbLogLevel.getItems().setAll("OFF","SEVERE","WARNING","INFO","CONFIG","FINE","FINER","FINEST");

        // 초기 값: LogSetup 저장값(Preferences) → 시스템 프로퍼티 → INFO
        String init = LogSetup.getSavedLevel().getName();
        if (!cbLogLevel.getItems().contains(init)) init = "INFO";
        cbLogLevel.setValue(init);

        // 콤보 변경 시 즉시 반영 + 저장
        cbLogLevel.setOnAction(e -> {
            String sel = cbLogLevel.getValue();
            if (sel == null || sel.isBlank()) return;
            Level lvl = LogSetup.levelOf(sel);
            LogSetup.setLevel(lvl, true); // 콘솔/파일 동시에 반영 + Preferences 저장
        });
    }
}
