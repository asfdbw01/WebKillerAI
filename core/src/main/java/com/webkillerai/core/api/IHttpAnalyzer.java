// IHttpAnalyzer.java
package com.webkillerai.core.api;

import com.webkillerai.core.model.HttpResponseData;
import java.net.URI;

/** HTTP 분석 최소 계약: URL을 받아 응답 모델을 돌려준다. */
public interface IHttpAnalyzer extends AutoCloseable {
    HttpResponseData analyze(URI url);
    @Override default void close() throws Exception {}
}
