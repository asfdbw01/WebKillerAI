package com.webkillerai.app.ui;

import com.webkillerai.core.model.Mode;        // ★ 변경: 최상위 Mode 사용
import com.webkillerai.core.model.ScanConfig;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.Objects;

/** 상단 메뉴바에 "Mode" 메뉴를 추가해 런타임에 모드/증거표시를 스위칭.
 *  - 기본 모드: SAFE (ScanConfig 기본값 그대로)
 *  - 모드: SAFE / SAFE_PLUS / (AGGRESSIVE 또는 AGGRESSIVE_LITE 중 프로젝트에 존재하는 값)
 *  - 옵션: 리포트에서 requestLine + snippet 표시 (HTML/JSON 렌더 토글)
 *  - 스캔 중엔 변경 막기(setScanInProgress)로 UX/레이스가드
 */
public final class ModeMenu {

    private final ScanConfig cfg;
    private final Runnable onChanged; // UI 갱신/배너 로그 등에 사용 (nullable OK)

    // ★ final 제거: 빌드 시점에 동적으로 생성
    private JRadioButtonMenuItem miSafe;
    private JRadioButtonMenuItem miSafePlus;
    private JRadioButtonMenuItem miAggressive; // AGGRESSIVE 또는 AGGRESSIVE_LITE 레이블/모드로 생성될 수 있음
    private JCheckBoxMenuItem miEvidence;

    private volatile boolean scanInProgress = false;

    public ModeMenu(ScanConfig cfg, Runnable onChanged) {
        this.cfg = Objects.requireNonNull(cfg, "cfg");
        this.onChanged = onChanged;
    }

    /** 상단 메뉴바에 붙일 "Mode" 메뉴 생성 */
    public JMenu build() {
        JMenu modeMenu = new JMenu("Mode");

        // 동적 생성
        miSafe = new JRadioButtonMenuItem("SAFE");
        miSafePlus = new JRadioButtonMenuItem("SAFE_PLUS");

        Mode aggressiveMode = resolveAggressiveMode(); // AGGRESSIVE 우선, 없으면 AGGRESSIVE_LITE, 둘 다 없으면 null
        if (aggressiveMode != null) {
            miAggressive = new JRadioButtonMenuItem(aggressiveMode.name());
        }

        miEvidence = new JCheckBoxMenuItem("Show requestLine + snippet in reports");

        ButtonGroup g = new ButtonGroup();
        g.add(miSafe);
        g.add(miSafePlus);
        if (miAggressive != null) g.add(miAggressive);

        // 현재 설정 반영
        Mode m = cfg.getMode();
        if (m == Mode.SAFE_PLUS) {
            miSafePlus.setSelected(true);
        } else if (aggressiveMode != null && m == aggressiveMode) {
            miAggressive.setSelected(true);
        } else {
            miSafe.setSelected(true); // 디폴트 SAFE
        }

        // Evidence 표시(시스템 프로퍼티 기반). 기본은 SAFE=off, SAFE_PLUS=on 권장
        boolean defaultEvidence = (m == Mode.SAFE_PLUS);
        boolean effective = readEvidenceProp(defaultEvidence);
        miEvidence.setSelected(effective);

        // 리스너
        miSafe.addActionListener(applyMode(Mode.SAFE));
        miSafePlus.addActionListener(applyMode(Mode.SAFE_PLUS));
        if (miAggressive != null) {
            miAggressive.addActionListener(applyMode(aggressiveMode));
        }
        miEvidence.addActionListener(e -> {
            if (guardBusy()) return;
            setEvidenceProp(miEvidence.isSelected());
            fireChanged();
        });

        modeMenu.add(miSafe);
        modeMenu.add(miSafePlus);
        if (miAggressive != null) modeMenu.add(miAggressive);
        modeMenu.addSeparator();
        modeMenu.add(miEvidence);
        return modeMenu;
    }

    /** 스캔 중 상태를 외부에서 알려주면 메뉴를 비활성화(레이스 가드) */
    public void setScanInProgress(boolean inProgress) {
        this.scanInProgress = inProgress;
        boolean enabled = !inProgress;
        if (miSafe != null) miSafe.setEnabled(enabled);
        if (miSafePlus != null) miSafePlus.setEnabled(enabled);
        if (miAggressive != null) miAggressive.setEnabled(enabled);
        if (miEvidence != null) miEvidence.setEnabled(enabled);
    }

    /** 배너 텍스트(로그/상단 상태표시 등) */
    public static String banner(ScanConfig cfg) {
        return "[MODE] " + (cfg.getMode() == null ? "SAFE" : cfg.getMode().name());
    }

    // ---------------- internal ----------------

    private ActionListener applyMode(Mode mode) {
        return e -> {
            if (guardBusy()) return;
            cfg.setMode(mode);
            // SAFE_PLUS로 전환 시 evidence 기본 on, SAFE는 off (사용자 선택 유지하려면 아래 두 블록을 주석 처리)
            if (mode == Mode.SAFE_PLUS && !miEvidence.isSelected()) {
                setEvidenceProp(true); miEvidence.setSelected(true);
            }
            if (mode == Mode.SAFE && miEvidence.isSelected()) {
                setEvidenceProp(false); miEvidence.setSelected(false);
            }
            fireChanged();
        };
    }

    private boolean guardBusy() {
        if (!scanInProgress) return false;
        JOptionPane.showMessageDialog(null,
                "스캔 실행 중에는 모드를 변경할 수 없습니다.\n작업이 끝난 후 다시 시도하세요.",
                "Busy", JOptionPane.WARNING_MESSAGE);
        return true;
    }

    private void fireChanged() { if (onChanged != null) onChanged.run(); }

    private static boolean readEvidenceProp(boolean def) {
        String p = System.getProperty("wk.report.showEvidenceDetails", "").trim().toLowerCase();
        if (p.equals("on") || p.equals("true") || p.equals("1")) return true;
        if (p.equals("off") || p.equals("false") || p.equals("0")) return false;
        return def;
    }

    private static void setEvidenceProp(boolean on) {
        System.setProperty("wk.report.showEvidenceDetails", on ? "on" : "off");
    }

    /** 프로젝트의 Mode에 AGGRESSIVE가 있으면 그것을, 없으면 AGGRESSIVE_LITE를, 둘 다 없으면 null 반환 */
    private static Mode resolveAggressiveMode() {
        try {
            return Mode.valueOf("AGGRESSIVE");
        } catch (IllegalArgumentException e) {
            try {
                return Mode.valueOf("AGGRESSIVE_LITE");
            } catch (IllegalArgumentException e2) {
                return null;
            }
        }
    }
}
