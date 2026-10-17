package com.imdomestic.mc.router;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Iterator;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * k8s API 客户端，用 Pod 里挂载的 ServiceAccount 凭据。能做什么由 RBAC 决定：
 * 读写 GameServer、创建 GameServerAllocation，见 k8s/apps/mc。
 *
 * <p>没用 fabric8 / client-java：插件只需要 list 和 watch 一种资源，而那两个库要把几十 MB 的
 * 依赖 shade 进 Velocity 插件。JSON 用 Velocity 自带的 Gson。
 */
final class KubeClient {
  private static final Path SERVICE_ACCOUNT = Path.of("/var/run/secrets/kubernetes.io/serviceaccount");

  private final HttpClient http;
  private final URI base;

  private KubeClient(HttpClient http, URI base) {
    this.http = http;
    this.base = base;
  }

  /** 不在 Pod 里运行（没有 KUBERNETES_SERVICE_HOST）时返回空。 */
  static Optional<KubeClient> inCluster() throws IOException, GeneralSecurityException {
    String host = System.getenv("KUBERNETES_SERVICE_HOST");
    String port = System.getenv("KUBERNETES_SERVICE_PORT");
    if (host == null || port == null) {
      return Optional.empty();
    }
    KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
    trust.load(null, null);
    try (InputStream in = Files.newInputStream(SERVICE_ACCOUNT.resolve("ca.crt"))) {
      int i = 0;
      for (Certificate cert : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
        trust.setCertificateEntry("ca-" + i++, cert);
      }
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trust);
    SSLContext tls = SSLContext.getInstance("TLS");
    tls.init(null, tmf.getTrustManagers(), null);
    HttpClient http = HttpClient.newBuilder()
        .sslContext(tls)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    String authority = host.contains(":") ? "[" + host + "]" : host;
    return Optional.of(new KubeClient(http, URI.create("https://" + authority + ":" + port)));
  }

  static String podNamespace() throws IOException {
    return Files.readString(SERVICE_ACCOUNT.resolve("namespace")).strip();
  }

  JsonObject get(String pathAndQuery) throws IOException, InterruptedException {
    HttpResponse<String> response = http.send(request(pathAndQuery, Duration.ofSeconds(30)),
        HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != 200) {
      throw new IOException("GET " + pathAndQuery + " -> " + response.statusCode() + ": " + response.body());
    }
    return JsonParser.parseString(response.body()).getAsJsonObject();
  }

  JsonObject post(String path, JsonObject body) throws IOException, InterruptedException {
    HttpRequest request = builder(path, Duration.ofSeconds(30))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
        .build();
    HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() / 100 != 2) {
      throw new IOException("POST " + path + " -> " + response.statusCode() + ": " + response.body());
    }
    return JsonParser.parseString(response.body()).getAsJsonObject();
  }

  /** 已经不存在（404）也算成功。 */
  void delete(String path) throws IOException, InterruptedException {
    HttpRequest request = builder(path, Duration.ofSeconds(30)).DELETE().build();
    HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() / 100 != 2 && response.statusCode() != 404) {
      throw new IOException("DELETE " + path + " -> " + response.statusCode() + ": " + response.body());
    }
  }

  /** 阻塞读取 watch 流，每个事件回调一次；服务端按 timeoutSeconds 关流时正常返回。 */
  void watch(String pathAndQuery, Consumer<JsonObject> onEvent) throws IOException, InterruptedException {
    // 不设请求超时：watch 本来就是长连接，结束由服务端的 timeoutSeconds 决定。
    HttpResponse<Stream<String>> response = http.send(request(pathAndQuery, null),
        HttpResponse.BodyHandlers.ofLines());
    try (Stream<String> lines = response.body()) {
      if (response.statusCode() != 200) {
        throw new IOException("WATCH " + pathAndQuery + " -> " + response.statusCode());
      }
      Iterator<String> it = lines.iterator();
      while (it.hasNext()) {
        String line = it.next();
        if (!line.isBlank()) {
          onEvent.accept(JsonParser.parseString(line).getAsJsonObject());
        }
      }
    }
  }

  private HttpRequest request(String pathAndQuery, Duration timeout) throws IOException {
    return builder(pathAndQuery, timeout).GET().build();
  }

  private HttpRequest.Builder builder(String pathAndQuery, Duration timeout) throws IOException {
    // 每次都重新读：投射进来的 token 会定期轮换。
    String token = Files.readString(SERVICE_ACCOUNT.resolve("token")).strip();
    HttpRequest.Builder builder = HttpRequest.newBuilder(base.resolve(pathAndQuery))
        .header("Authorization", "Bearer " + token)
        .header("Accept", "application/json");
    if (timeout != null) {
      builder.timeout(timeout);
    }
    return builder;
  }
}
