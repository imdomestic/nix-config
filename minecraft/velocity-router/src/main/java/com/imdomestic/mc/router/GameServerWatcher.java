package com.imdomestic.mc.router;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;

/**
 * list + watch 指定命名空间里带 {@link Routes#LABEL_KIND} 的 GameServer，把变化交给
 * {@link Routes}。标准的 informer 循环：先 list 拿全量和 resourceVersion，再从这个版本 watch；
 * 版本过期（410 Gone）就重新 list，其他错误退避后重来。
 */
final class GameServerWatcher implements Runnable {
  private static final long MAX_BACKOFF_MS = 30_000;

  private final KubeClient kube;
  private final String collection;
  private final Routes routes;
  private final Logger logger;
  private volatile boolean running = true;
  private String resourceVersion;

  GameServerWatcher(KubeClient kube, String namespace, Routes routes, Logger logger) {
    this.kube = kube;
    this.collection = "/apis/agones.dev/v1/namespaces/" + namespace + "/gameservers?labelSelector="
        + URLEncoder.encode(Routes.LABEL_KIND, StandardCharsets.UTF_8);
    this.routes = routes;
    this.logger = logger;
  }

  void stop() {
    running = false;
  }

  @Override
  public void run() {
    long backoff = 1_000;
    while (running) {
      try {
        relist();
        backoff = 1_000;
        while (running) {
          kube.watch(collection + "&watch=1&allowWatchBookmarks=true&timeoutSeconds=300&resourceVersion="
              + resourceVersion, this::onEvent);
        }
      } catch (Gone e) {
        logger.info("watch 的 resourceVersion 过期，重新 list");
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      } catch (Exception e) {
        if (!running) {
          return;
        }
        logger.warn("GameServer watch 出错，{} 毫秒后重试：{}", backoff, e.toString());
        try {
          Thread.sleep(backoff);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          return;
        }
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
      }
    }
  }

  private void relist() throws Exception {
    JsonObject list = kube.get(collection);
    List<JsonObject> items = new ArrayList<>();
    for (JsonElement item : list.getAsJsonArray("items")) {
      items.add(item.getAsJsonObject());
    }
    routes.replaceAll(items);
    resourceVersion = list.getAsJsonObject("metadata").get("resourceVersion").getAsString();
  }

  private void onEvent(JsonObject event) {
    String type = event.get("type").getAsString();
    JsonObject object = event.getAsJsonObject("object");
    switch (type) {
      case "ADDED", "MODIFIED" -> routes.upsert(object);
      case "DELETED" -> routes.remove(object.getAsJsonObject("metadata").get("name").getAsString());
      case "BOOKMARK" -> { }
      case "ERROR" -> {
        if (object.has("code") && object.get("code").getAsInt() == 410) {
          throw new Gone();
        }
        throw new IllegalStateException("watch ERROR: " + object);
      }
      default -> logger.warn("未知的 watch 事件类型：{}", type);
    }
    JsonObject metadata = object.getAsJsonObject("metadata");
    if (metadata != null && metadata.has("resourceVersion")) {
      resourceVersion = metadata.get("resourceVersion").getAsString();
    }
  }

  private static final class Gone extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }
}
