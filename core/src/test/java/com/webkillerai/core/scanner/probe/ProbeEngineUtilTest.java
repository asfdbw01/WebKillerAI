package com.webkillerai.core.scanner.probe;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class ProbeEngineUtilTest {

  @Test
  void requestLine_basic() throws Exception {
    URI u = new URI("https://ex.com/a?b=1");
    assertEquals("GET https://ex.com/a?b=1 HTTP/1.1", ProbeEngine.requestLine("GET", u));
  }

  @Test
  void snippetAround_whenTokenPresent() {
    String body = "......abcDEFTOKENxyz......";
    String snip = ProbeEngine.snippetAround(body, "TOKEN", 5);
    assertTrue(snip.contains("TOKEN"));
    assertTrue(snip.length() <= "TOKEN".length() + 10);
  }

  @Test
  void snippetAround_whenTokenMissing_returnsHead() {
    String body = "0123456789abcdefghij";
    String snip = ProbeEngine.snippetAround(body, "zzz", 5);
    assertEquals(10, snip.length()); // r*2 = 10
  }

  @Test
  void maskSensitive_passwdAndApiKey() {
    String s = "root:x:12345:987:/root:/bin/bash\napiKey=abcdef123456";
    String m = ProbeEngine.maskSensitive(s);
    assertTrue(m.contains("root:x:***"));
    assertTrue(m.contains("apiKey=***"));
    assertFalse(m.contains("abcdef123456"));
  }
}
