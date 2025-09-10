package com.webkillerai.app.ui;

import com.webkillerai.core.model.Mode;       // ★ 추가: 최상위 Mode
import com.webkillerai.core.model.ScanConfig;
import javafx.beans.property.*;

import java.nio.file.Path;

public final class AppState {

    private final ScanConfig cfg;

    // UI 바인딩용 프로퍼티들
    private final StringProperty target = new SimpleStringProperty("https://example.com");
    private final ObjectProperty<Mode> mode = new SimpleObjectProperty<>(Mode.SAFE);  // ★ 변경
    private final IntegerProperty rps = new SimpleIntegerProperty(7);
    private final IntegerProperty concurrency = new SimpleIntegerProperty(2);
    private final IntegerProperty maxDepth = new SimpleIntegerProperty(2);
    private final BooleanProperty sameDomain = new SimpleBooleanProperty(true);
    private final BooleanProperty followRedirects = new SimpleBooleanProperty(true);
    private final BooleanProperty showEvidenceDetails = new SimpleBooleanProperty(false); // SAFE 기본 false

    public AppState(ScanConfig cfg) {
        this.cfg = cfg;

        // ScanConfig → UI 초기값
        target.set(cfg.getTarget() != null ? cfg.getTarget() : "https://example.com");
        mode.set(cfg.getMode() == null ? Mode.SAFE : cfg.getMode());               // ★ 변경
        rps.set(cfg.getRps());
        concurrency.set(cfg.getConcurrency());
        maxDepth.set(cfg.getMaxDepth());
        sameDomain.set(cfg.isSameDomainOnly());
        followRedirects.set(cfg.isFollowRedirects());
        showEvidenceDetails.set(mode.get() == Mode.SAFE_PLUS);                     // ★ 변경

        // 모드 바뀌면, evidence 토글 기본값을 살짝 맞춰줌(사용자가 바꿨다면 그대로 둠)
        mode.addListener((obs, o, n) -> {
            if (o == null && n == null) return;
            if (n == Mode.SAFE_PLUS && !showEvidenceDetails.isBound()) {           // ★ 변경
                // SAFE_PLUS로 들어오면 기본적으로 ON으로 올려줌(사용자가 직접 끄면 그대로 유지)
                if (!showEvidenceDetails.get()) showEvidenceDetails.set(true);
            }
        });
    }

    /** UI → ScanConfig 반영 (스캔 직전에 호출) */
    public void applyToConfig() {
        cfg.setTarget(target.get());
        cfg.setMode(mode.get() == null ? Mode.SAFE : mode.get());                  // ★ 변경
        cfg.setRps(Math.max(1, rps.get()));
        cfg.setConcurrency(Math.max(1, concurrency.get()));
        cfg.setSameDomainOnly(sameDomain.get());
        cfg.setFollowRedirects(followRedirects.get());
        cfg.setMaxDepth(Math.max(0, maxDepth.get()));
        cfg.setOutputDir(Path.of(System.getProperty("wk.out.dir", "out")));

        // HTML 리포트의 증거 표시 토글 (Exporter에서 읽음)
        System.setProperty(
                "wk.report.showEvidenceDetails",
                showEvidenceDetails.get() ? "on" : "off"
        );
    }

    public ScanConfig getConfig() { return cfg; }

    // ---- properties (컨트롤러 바인딩에서 씀) ----
    public StringProperty targetProperty() { return target; }
    public ObjectProperty<Mode> modeProperty() { return mode; }                    // ★ 변경
    public IntegerProperty rpsProperty() { return rps; }
    public IntegerProperty concurrencyProperty() { return concurrency; }
    public IntegerProperty maxDepthProperty() { return maxDepth; }
    public BooleanProperty sameDomainProperty() { return sameDomain; }
    public BooleanProperty followRedirectsProperty() { return followRedirects; }
    public BooleanProperty showEvidenceDetailsProperty() { return showEvidenceDetails; }
}
