package com.webkillerai.app.ui;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.prefs.Preferences;

/**
 * AdvancedFilterPresetStore
 * - 프리셋을 Preferences에 라인 포맷("name=BASE64(json)")으로 저장/불러오기
 * - JSON은 Base64로 인코딩하여 개행/특수문자 안전
 * - 이름은 간단 정제(sanitize) 후 저장
 * - 키: wk.ui.filter.presets.v1
 */
public final class AdvancedFilterPresetStore {

    private static final String PREF_KEY = "wk.ui.filter.presets.v1";
    private static final int MAX_LEN_HINT = 8 * 1024; // 일부 플랫폼에서 값 길이 제한 힌트(잘림 가드)

    private final Preferences prefs;

    public AdvancedFilterPresetStore(Class<?> ownerClass) {
        this.prefs = Preferences.userNodeForPackage(ownerClass);
    }

    /** 모든 프리셋을 이름->JSON 문자열로 로드(삽입 순서 유지). 손상 라인은 무시. */
    public Map<String, String> loadAll() {
        String blob = prefs.get(PREF_KEY, "");
        if (blob.isEmpty()) return new LinkedHashMap<>();
        Map<String, String> out = new LinkedHashMap<>();
        for (String line : blob.split("\\R")) {
            if (line.isBlank()) continue;
            int idx = line.indexOf('=');
            if (idx <= 0) continue; // 이름이 비정상
            String name = line.substring(0, idx);
            String b64  = line.substring(idx + 1);
            try {
                String json = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
                out.put(name, json);
            } catch (IllegalArgumentException ignore) {
                // 손상된 라인 → 스킵
            }
        }
        return out;
    }

    /** 모든 프리셋을 한 번에 저장. 너무 길면 잘라서 저장(임시 가드). */
    public void saveAll(Map<String, String> presets) {
        StringBuilder sb = new StringBuilder();
        presets.forEach((name, json) -> {
            String safeName = sanitizeName(name);
            String b64 = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
            sb.append(safeName).append('=').append(b64).append('\n');
        });
        String s = sb.toString();
        if (s.length() > MAX_LEN_HINT) {
            s = s.substring(0, MAX_LEN_HINT); // 임시 가드: 향후 파일 import/export로 확장 권장
        }
        prefs.put(PREF_KEY, s);
        try { prefs.flush(); } catch (Exception ignore) {}
    }

    /** 단일 프리셋 저장(동일 이름 덮어쓰기). */
    public void savePreset(String name, String jsonState) {
        var all = new LinkedHashMap<>(loadAll());
        all.put(sanitizeName(name), jsonState);
        saveAll(all);
    }

    /** 단일 프리셋 삭제. */
    public void deletePreset(String name) {
        var all = new LinkedHashMap<>(loadAll());
        if (all.remove(name) != null) saveAll(all);
    }

    /** 프리셋 존재 여부. */
    public boolean exists(String name) {
        return loadAll().containsKey(name);
    }

    /** 프리셋 JSON 조회. */
    public Optional<String> getPreset(String name) {
        return Optional.ofNullable(loadAll().get(name));
    }

    /** 프리셋 이름 목록(삽입 순서). */
    public List<String> listNames() {
        return new ArrayList<>(loadAll().keySet());
    }

    /** 전체 초기화(주의). */
    public void clearAll() {
        prefs.remove(PREF_KEY);
        try { prefs.flush(); } catch (Exception ignore) {}
    }

    // -------- 내부 유틸 --------

    /** 프리셋 이름 정제: 개행/=/양끝 공백 제거, 과도한 길이 제한. */
    private static String sanitizeName(String name) {
        if (name == null) return "preset";
        String s = name.strip()
                .replaceAll("[=\\r\\n]", " ")
                .replaceAll("\\s{2,}", " ");
        if (s.isEmpty()) s = "preset";
        if (s.length() > 64) s = s.substring(0, 64);
        return s;
    }
}
