package dev;

import com.sun.net.httpserver.*;
import javax.net.ssl.*;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate; // ✅ 필요한 것만
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

// BouncyCastle (표준 공개 API)
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SmokeTarget {

  static void add(HttpServer s, String path, HttpHandler h) { s.createContext(path, h); }

  public static void main(String[] args) throws Exception {
    // --- HTTP 8080
    HttpServer http = HttpServer.create(new InetSocketAddress(8080), 0);
    wireEndpoints(http, false);
    http.setExecutor(Executors.newFixedThreadPool(8));
    http.start();
    System.out.println("[WKAI] HTTP  server on  http://localhost:8080");

    // --- HTTPS 8443 (자가서명 p12 자동 생성/로드)
    try {
      HttpsServer https = HttpsServer.create(new InetSocketAddress(8443), 0);
      SSLContext ssl = buildOrLoadSSLContext(
          new File("smoke-keystore.p12"),
          "changeit".toCharArray(),
          "smoke"
      );
      https.setHttpsConfigurator(new HttpsConfigurator(ssl));
      wireEndpoints(https, true);
      https.setExecutor(Executors.newFixedThreadPool(8));
      https.start();
      System.out.println("[WKAI] HTTPS server on https://localhost:8443 (self-signed)");
    } catch (Exception e) {
      System.out.println("[WKAI] HTTPS disabled (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
    }
  }

  // 공통 엔드포인트 배선
  static void wireEndpoints(HttpServer s, boolean isHttps) {
    // robots.txt
    add(s, "/robots.txt", ex -> {
      resp(ex, 200, "text/plain", "User-agent: *\nAllow: /\n");
    });

    // 인덱스
    add(s, "/", ex -> {
      String html =
        "<html><body>" +
        "  <h3>WKAI Smoke Index</h3>" +
        "  <ul>" +
        "    <li><a href=\"/redir?next=https://example.org\">/redir?next=https://example.org</a></li>" +
        "    <li><a href=\"/file?file=../../../../etc/passwd\">/file?file=../../../../etc/passwd</a></li>" +
        "    <li><a href=\"/file?file=../../../../windows/win.ini\">/file?file=../../../../windows/win.ini</a></li>" +
        "    <li><a href=\"/ssti?q={{7*7}}WKAI\">/ssti?q={{7*7}}WKAI</a></li>" +
        "    <li><a href=\"/ssti?q=%24%7B7*7%7D\">/ssti?q=${7*7}</a></li>" +
        "    <li><a href=\"/ssti?q=%3C%25%3D7*7%25%3E\">/ssti?q=&lt;%=7*7%&gt;</a></li>" +
        "    <li><a href=\"/cors?x=1\">/cors?x=1</a></li>" +
        "    <li><a href=\"/echo?q=%3Cscript%3Ealert(1)%3C/script%3E\">/echo?q=&lt;script&gt;alert(1)&lt;/script&gt;</a></li>" +
        "    <li><a href=\"/prod?id='\">/prod?id='</a></li>" +
        "    <li><a href=\"/mixed\">/mixed (HTTPS에서 Mixed Content 트리거)</a></li>" +
        "  </ul>" +
        "  <p>Mode: " + (isHttps ? "HTTPS" : "HTTP") + "</p>" +
        "</body></html>";
      resp(ex, 200, "text/html", html);
    });

    // Mixed Content (HTTPS 문서에서만 의미)
    add(s, "/mixed", ex -> {
      String html =
        "<html><head>" +
        "  <link rel=\"stylesheet\" href=\"http://example.org/style.css\">" +
        "</head><body>" +
        "  <img src=\"http://example.org/a.png\">" +
        "  <p>Mode: " + (isHttps ? "HTTPS" : "HTTP") + "</p>" +
        "</body></html>";
      resp(ex, 200, "text/html", html);
    });

    // Open Redirect
    add(s, "/redir", ex -> {
      var q = query(ex.getRequestURI());
      String loc = Stream.of("next", "url", "returnUrl", "redirect")
              .map(q::get)
              .filter(Objects::nonNull)
              .findFirst()
              .orElse("https://example.org");
      ex.getResponseHeaders().set("Location", loc);
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });

    // Path Traversal(LFI-ish)
    add(s, "/file", ex -> {
      var q = query(ex.getRequestURI());
      String f = q.getOrDefault("file", "");
      String body;
      if (f.toLowerCase().contains("etc/passwd")) {
        body = String.join("\n",
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
        ) + "\n";
      } else if (f.toLowerCase().contains("windows/win.ini")) {
        body = String.join("\r\n",
            "[fonts]",
            "; for 16-bit app support",
            "[extensions]",
            "mscoree.dll=1"
        ) + "\r\n";
      } else {
        body = "[nope]";
      }
      resp(ex, 200, "text/plain", body);
    });

    // SSTI 라이트
    add(s, "/ssti", ex -> {
      var q = query(ex.getRequestURI());
      String v = q.getOrDefault("q", "");
      String out = v;
      if (v.contains("{{7*7}}") || v.contains("${7*7}") || v.contains("<%=7*7%>")) {
        out = out.replace("{{7*7}}", "49WKAI")
                 .replace("${7*7}",  "49WKAI")
                 .replace("<%=7*7%>", "49WKAI");
      }
      resp(ex, 200, "text/html", "<div>" + out + "</div>");
    });

    // CORS 미스컨피그
    add(s, "/cors", ex -> {
      Headers h = ex.getResponseHeaders();
      h.set("Access-Control-Allow-Origin", "*");
      h.set("Access-Control-Allow-Credentials", "true");
      h.add("Vary", "Origin");
      if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
        h.set("Access-Control-Allow-Methods", "GET,OPTIONS");
        h.set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
        ex.sendResponseHeaders(204, -1); ex.close(); return;
      }
      resp(ex, 200, "text/plain", "ok");
    });

    // XSS Reflected
    add(s, "/echo", ex -> {
      var q = query(ex.getRequestURI());
      String v = q.getOrDefault("q", "");
      resp(ex, 200, "text/html", "<div>" + v + "</div>");
    });

    // SQLi Error
    add(s, "/prod", ex -> {
      var q = query(ex.getRequestURI());
      String id = q.getOrDefault("id", "");
      String body = id.contains("'")
          ? "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
          : "ok";
      resp(ex, 200, "text/html", body);
    });
  }

  // ===== HTTPS 유틸 (BC로 자가서명 p12 생성/로드) =====
  static SSLContext buildOrLoadSSLContext(File p12File, char[] password, String alias) throws Exception {
    // ✅ BC Provider 등록 (한 번만)
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    KeyStore ks = KeyStore.getInstance("PKCS12");

    if (p12File.exists()) {
      try (InputStream in = new FileInputStream(p12File)) {
        ks.load(in, password);
      }
    } else {
      // 새로 생성
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);
      KeyPair kp = kpg.generateKeyPair();

      X509Certificate cert = generateSelfSigned("localhost", kp);
      ks.load(null, null);
      ks.setKeyEntry(alias, kp.getPrivate(), password, new java.security.cert.Certificate[]{cert}); // ✅ 완전수식

      try (OutputStream out = new FileOutputStream(p12File)) {
        ks.store(out, password);
      }
      try {
        p12File.setReadable(false, false); p12File.setReadable(true, true);
        p12File.setWritable(false, false); p12File.setWritable(true, true);
      } catch (Throwable ignore) {}
    }

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(ks, password);

    SSLContext ssl = SSLContext.getInstance("TLS");
    ssl.init(kmf.getKeyManagers(), null, new SecureRandom());
    return ssl;
  }

  static X509Certificate generateSelfSigned(String cn, KeyPair kp) throws Exception {
    X500Name subject = new X500Name("CN=" + cn);
    BigInteger serial = new BigInteger(64, new SecureRandom());
    Date notBefore = Date.from(ZonedDateTime.now().minus(1, ChronoUnit.DAYS).toInstant());
    Date notAfter  = Date.from(ZonedDateTime.now().plusYears(5).toInstant());

    // SubjectAltName: DNS:localhost, IP:127.0.0.1
    GeneralName[] san = new GeneralName[] {
        new GeneralName(GeneralName.dNSName, "localhost"),
        new GeneralName(GeneralName.iPAddress, "127.0.0.1")
    };
    GeneralNames subjectAltNames = new GeneralNames(san);

    JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        subject, serial, notBefore, notAfter, subject, kp.getPublic());

    // 키용도 / 확장 (❗ Extension은 BC 패키지로 완전수식)
    builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, subjectAltNames);
    builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
    var holder = builder.build(signer);
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
  }

  // ===== 공통 유틸 =====
  static Map<String,String> query(URI u){
    Map<String,String> m = new LinkedHashMap<>();
    String q = u.getRawQuery(); if (q==null) return m;
    for (String p: q.split("&")) {
      int i = p.indexOf('=');
      String k = i<0? p : p.substring(0,i);
      String v = i<0? "" : p.substring(i+1);
      m.put(urlDecode(k), urlDecode(v));
    }
    return m;
  }
  static String urlDecode(String s){
    try { return URLDecoder.decode(s, StandardCharsets.UTF_8); } catch(Exception e){ return s; }
  }
  static void resp(HttpExchange ex, int code, String ct, String body) throws IOException {
    byte[] b = body.getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", ct+"; charset=utf-8");
    // 보안 헤더 일부러 누락(스캐너 테스트 목적)
    ex.sendResponseHeaders(code, b.length);
    try (OutputStream os = ex.getResponseBody()) { os.write(b); }
  }
}
