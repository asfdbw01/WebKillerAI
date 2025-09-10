package com.webkillerai.core.service.export;

import com.webkillerai.core.model.ScanConfig;
import com.webkillerai.core.model.VulnResult;

import java.nio.file.Path;
import java.util.List;

/** 스캔 결과를 보고서 형태로 내보내는 책임 (확장: JSON/HTML/PDF 등) */
public interface ReportExporter {
    /**
     * @param baseDir   출력 루트 (null이면 "out")
     * @param cfg       스캔 설정(타깃/스코프 등 메타에 포함)
     * @param results   탐지 이슈 목록
     * @param startedIso 스캔 시작 시각(ISO-8601)
     * @return 생성된 파일의 경로
     */
    Path export(Path baseDir, ScanConfig cfg, List<VulnResult> results, String startedIso) throws Exception;
}
