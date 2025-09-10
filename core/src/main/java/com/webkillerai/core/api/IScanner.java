// IScanner.java
package com.webkillerai.core.api;

import com.webkillerai.core.model.HttpResponseData;
import com.webkillerai.core.model.VulnResult;
import java.util.List;

/** 스캐너 최소 계약: HTTP 응답을 받아 이슈 리스트를 돌려준다. */
public interface IScanner {
    List<VulnResult> scan(HttpResponseData resp);
}
