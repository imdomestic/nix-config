package com.imdomestic.mc.agones;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Agones SDK sidecar 的 REST 接口（localhost:$AGONES_SDK_HTTP_PORT）。
 *
 * <p>所有调用都是异步的，失败时 future 带异常结束，不在这里重试：重试策略属于调用方。
 * 接口定义见 https://agones.dev/site/docs/guides/client-sdks/rest/ 。
 */
public final class AgonesSdk {
  private static final Duration TIMEOUT = Duration.ofSeconds(5);

  private final HttpClient http;
  private final URI base;

  AgonesSdk(URI base) {
    this.base = base;
    this.http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
  }

  /** 不在 Agones 下运行（没有 sidecar 注入的端口变量）时返回空。 */
  public static Optional<AgonesSdk> fromEnvironment() {
    String port = System.getenv("AGONES_SDK_HTTP_PORT");
    if (port == null || port.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(new AgonesSdk(URI.create("http://localhost:" + port.trim())));
  }

  public CompletableFuture<Void> ready() {
    return send("POST", "/ready", "{}", Set.of());
  }

  public CompletableFuture<Void> health() {
    return send("POST", "/health", "{}", Set.of());
  }

  public CompletableFuture<Void> allocate() {
    return send("POST", "/allocate", "{}", Set.of());
  }

  public CompletableFuture<Void> shutdown() {
    return send("POST", "/shutdown", "{}", Set.of());
  }

  /** SDK 设置的 label 会被 Agones 加上 agones.dev/sdk- 前缀。 */
  public CompletableFuture<Void> setLabel(String key, String value) {
    return send("PUT", "/metadata/label", "{\"key\":" + quote(key) + ",\"value\":" + quote(value) + "}", Set.of());
  }

  /** 值已经在列表里时 sidecar 回 409，当作成功：进出事件可能重复。 */
  public CompletableFuture<Void> listAdd(String list, String value) {
    return send("POST", "/v1beta1/lists/" + list + ":addValue", "{\"value\":" + quote(value) + "}", Set.of(409));
  }

  /** 值不在列表里时 sidecar 回 404，当作成功。 */
  public CompletableFuture<Void> listRemove(String list, String value) {
    return send("POST", "/v1beta1/lists/" + list + ":removeValue", "{\"value\":" + quote(value) + "}", Set.of(404));
  }

  private CompletableFuture<Void> send(String method, String path, String body, Set<Integer> alsoOk) {
    HttpRequest request = HttpRequest.newBuilder(base.resolve(path))
        .timeout(TIMEOUT)
        .header("Content-Type", "application/json")
        .method(method, HttpRequest.BodyPublishers.ofString(body))
        .build();
    return http.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenApply(response -> {
      int status = response.statusCode();
      if ((status / 100 != 2) && !alsoOk.contains(status)) {
        throw new AgonesException(method + " " + path + " -> " + status + ": " + response.body().strip());
      }
      return null;
    });
  }

  /** 只用于 UUID、label 这类短字符串，所以只处理 JSON 必须转义的字符。 */
  static String quote(String s) {
    StringBuilder out = new StringBuilder(s.length() + 2).append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        default -> {
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    return out.append('"').toString();
  }

  public static final class AgonesException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    AgonesException(String message) {
      super(message);
    }
  }
}
