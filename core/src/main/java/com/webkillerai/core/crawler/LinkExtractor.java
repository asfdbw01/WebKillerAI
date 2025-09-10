package com.webkillerai.core.crawler;

import java.net.URI;
import java.util.Set;

/** 페이지에서 절대 URL을 추출하는 전략 인터페이스. */
public interface LinkExtractor {
    /**
     * base 페이지에서 링크를 추출해 절대 URI 집합으로 반환.
     * 네트워크/파싱 예외는 호출자가 정책적으로 처리.
     */
    Set<URI> extract(URI base) throws Exception;
}
