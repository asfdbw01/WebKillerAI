package com.webkillerai.app.ui;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * AdvancedFilterBarViewModel — 프리셋 최소 훅
 *
 * 역할:
 *  - 현재 필터 상태를 JSON으로 export / JSON을 상태에 적용(apply)하는 람다를 받아
 *    프리셋 저장/불러오기를 Preferences에 위임한다.
 *
 * 사용 예:
 *  var vm = new AdvancedFilterBarViewModel(
 *      () -> filterState.toJson(),              // exportSupplier
 *      json -> { filterState.fromJson(json); refreshTable(); } // applyConsumer
 *  );
 *  // UI 바인딩:
 *  combo.setItems(vm.getPresetNames());
 *  combo.valueProperty().bindBidirectional(vm.selectedPresetProperty());
 *  saveBtn.setOnAction(e -> vm.savePreset(promptName()));
 *  applyBtn.setOnAction(e -> vm.applySelectedPreset());
 *  deleteBtn.setOnAction(e -> vm.deleteSelectedPreset());
 */
public class AdvancedFilterBarViewModel {

    // ---- 외부 연결(현재 필터 상태 <-> JSON) ----
    private Supplier<String> exportSupplier;   // 현재 필터 상태 → JSON
    private Consumer<String> applyConsumer;    // JSON → 필터 상태 적용

    // ---- 저장소 ----
    private final AdvancedFilterPresetStore presetStore =
            new AdvancedFilterPresetStore(AdvancedFilterBarViewModel.class);

    // ---- UI 바인딩 ----
    private final ObservableList<String> presetNames = FXCollections.observableArrayList();
    private final StringProperty selectedPreset = new SimpleStringProperty();

    // ---- 생성자 ----
    public AdvancedFilterBarViewModel(Supplier<String> exportSupplier,
                                      Consumer<String> applyConsumer) {
        this.exportSupplier = Objects.requireNonNull(exportSupplier, "exportSupplier");
        this.applyConsumer  = Objects.requireNonNull(applyConsumer,  "applyConsumer");
        refreshPresetNames();
    }

    /** DI/FXML을 위해 기본 생성 + 세터 주입도 지원 */
    public AdvancedFilterBarViewModel() {
        // no-op 기본 람다 (적용 전 반드시 세터로 주입)
        this.exportSupplier = () -> "{}";
        this.applyConsumer  = s -> {};
        refreshPresetNames();
    }

    // ---- 프리셋 API ----

    /** 프리셋 목록 재로딩 */
    public void refreshPresetNames() {
        presetNames.setAll(presetStore.listNames());
    }

    /** 현재 필터 상태를 이름으로 저장(덮어쓰기). */
    public void savePreset(String name) {
        if (name == null || name.isBlank()) return;
        String json = exportSupplier.get();
        presetStore.savePreset(name, json);
        refreshPresetNames();
        selectedPreset.set(name);
    }

    /** 선택된 프리셋 적용 */
    public void applySelectedPreset() {
        String name = getSelectedPreset();
        if (name == null || name.isBlank()) return;
        presetStore.getPreset(name).ifPresent(applyConsumer);
    }

    /** 선택된 프리셋 삭제 */
    public void deleteSelectedPreset() {
        String name = getSelectedPreset();
        if (name == null || name.isBlank()) return;
        presetStore.deletePreset(name);
        refreshPresetNames();
        selectedPreset.set(null);
    }

    /** 이름으로 즉시 적용(바이패스) */
    public void applyPresetByName(String name) {
        if (name == null || name.isBlank()) return;
        presetStore.getPreset(name).ifPresent(applyConsumer);
        selectedPreset.set(name);
    }

    /** 모든 프리셋을 Map으로 가져오기(이름->JSON) */
    public Map<String, String> getAllPresets() {
        return new LinkedHashMap<>(presetStore.loadAll());
    }

    // ---- 바인딩/세터 ----
    public ObservableList<String> getPresetNames() { return presetNames; }
    public StringProperty selectedPresetProperty() { return selectedPreset; }
    public String getSelectedPreset() { return selectedPreset.get(); }
    public void setSelectedPreset(String name) { selectedPreset.set(name); }

    public void setExportSupplier(Supplier<String> exportSupplier) {
        this.exportSupplier = Objects.requireNonNull(exportSupplier);
    }
    public void setApplyConsumer(Consumer<String> applyConsumer) {
        this.applyConsumer = Objects.requireNonNull(applyConsumer);
    }
}
