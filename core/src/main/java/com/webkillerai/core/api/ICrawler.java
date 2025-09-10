// ICrawler.java
package com.webkillerai.core.api;

import java.net.URI;
import java.util.List;

/** 크롤러 최소 계약: 시드 URL 목록을 돌려준다. */
public interface ICrawler extends AutoCloseable {
    List<URI> crawlSeeds();
    @Override default void close() throws Exception {}
}
