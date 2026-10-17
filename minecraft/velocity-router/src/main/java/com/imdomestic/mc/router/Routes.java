package com.imdomestic.mc.router;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import java.net.InetSocketAddress;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;

/**
 * GameServer 到 Velocity 后端的映射。只管理自己注册的后端，velocity.toml 里的静态后端不碰。
 *
 * <p>运营网络内部的标签约定（见 docs/minecraft-network-todo.md）：
 * <ul>
 *   <li>{@value #LABEL_KIND}：服务器类型，比如 lobby。没有这个标签的 GameServer 不路由。
 *   <li>{@value #LABEL_PROTOCOL}：后端的协议版本号，告诉 Velocity 上的 Via。
 * </ul>
 */
final class Routes {
  static final String LABEL_KIND = "mc.imdomestic.com/kind";
  static final String LABEL_PROTOCOL = "mc.imdomestic.com/protocol";
  static final String KIND_LOBBY = "lobby";

  /** Reserved 也算：它只是暂时不让 GSA 分配，玩家照样能连。 */
  private static final Set<String> ROUTABLE_STATES = Set.of("Ready", "Allocated", "Reserved");
  private static final int DEFAULT_PORT = 25565;

  record Route(String name, String kind, InetSocketAddress address, int protocol) {}

  private final ProxyServer proxy;
  private final Logger logger;
  private final Optional<ViaHook> via;
  private final int lobbySoftCap;
  private final Map<String, Route> routes = new HashMap<>();

  Routes(ProxyServer proxy, Logger logger, Optional<ViaHook> via, int lobbySoftCap) {
    this.proxy = proxy;
    this.logger = logger;
    this.via = via;
    this.lobbySoftCap = lobbySoftCap;
  }

  synchronized void replaceAll(List<JsonObject> gameServers) {
    Set<String> seen = new HashSet<>();
    for (JsonObject gs : gameServers) {
      seen.add(name(gs));
      upsert(gs);
    }
    for (String stale : Set.copyOf(routes.keySet())) {
      if (!seen.contains(stale)) {
        remove(stale);
      }
    }
  }

  synchronized void upsert(JsonObject gameServer) {
    String name = name(gameServer);
    Optional<Route> wanted = toRoute(gameServer);
    Route current = routes.get(name);
    if (wanted.isEmpty()) {
      remove(name);
      return;
    }
    if (wanted.get().equals(current)) {
      return;
    }
    if (current != null) {
      unregister(current);
    }
    register(wanted.get());
  }

  synchronized void remove(String name) {
    Route current = routes.get(name);
    if (current != null) {
      unregister(current);
    }
  }

  /**
   * 选一个大厅：优先人最多、但还没到软上限的那个，把人往少数几台上集中，空出来的大厅才能被
   * Fleet 缩容回收；都满了就挑人最少的。
   */
  synchronized Optional<RegisteredServer> pickLobby(RegisteredServer exclude) {
    Comparator<RegisteredServer> byPlayers = Comparator.comparingInt(s -> s.getPlayersConnected().size());
    List<RegisteredServer> lobbies = routes.values().stream()
        .filter(r -> KIND_LOBBY.equals(r.kind()))
        .map(r -> proxy.getServer(r.name()))
        .flatMap(Optional::stream)
        .filter(s -> exclude == null || !s.getServerInfo().equals(exclude.getServerInfo()))
        .sorted(byPlayers.reversed().thenComparing(s -> s.getServerInfo().getName()))
        .toList();
    return lobbies.stream()
        .filter(s -> s.getPlayersConnected().size() < lobbySoftCap)
        .findFirst()
        .or(() -> lobbies.stream().min(byPlayers));
  }

  private void register(Route route) {
    via.ifPresent(v -> {
      if (route.protocol() > 0) {
        v.setProtocol(route.name(), route.protocol());
      }
    });
    proxy.registerServer(new ServerInfo(route.name(), route.address()));
    routes.put(route.name(), route);
    logger.info("注册后端 {}（{}）→ {}", route.name(), route.kind(), route.address());
  }

  private void unregister(Route route) {
    proxy.getServer(route.name()).ifPresent(s -> proxy.unregisterServer(s.getServerInfo()));
    via.ifPresent(v -> v.forget(route.name()));
    routes.remove(route.name());
    logger.info("注销后端 {}", route.name());
  }

  private static String name(JsonObject gameServer) {
    return gameServer.getAsJsonObject("metadata").get("name").getAsString();
  }

  private static Optional<Route> toRoute(JsonObject gs) {
    JsonObject metadata = gs.getAsJsonObject("metadata");
    JsonObject status = gs.getAsJsonObject("status");
    if (metadata.has("deletionTimestamp") || status == null) {
      return Optional.empty();
    }
    String state = string(status, "state");
    if (state == null || !ROUTABLE_STATES.contains(state)) {
      return Optional.empty();
    }
    String address = podIp(status);
    if (address == null) {
      return Optional.empty();
    }
    JsonObject labels = metadata.getAsJsonObject("labels");
    String kind = labels == null ? null : string(labels, LABEL_KIND);
    String protocol = labels == null ? null : string(labels, LABEL_PROTOCOL);
    return Optional.of(new Route(name(gs), kind, new InetSocketAddress(address, port(status)),
        protocol == null ? -1 : Integer.parseInt(protocol)));
  }

  /** PortPolicy None 下没有 hostPort，Velocity 在集群里直接连 Pod IP；status.address 是节点地址。 */
  private static String podIp(JsonObject status) {
    JsonArray addresses = status.getAsJsonArray("addresses");
    if (addresses != null) {
      for (JsonElement e : addresses) {
        JsonObject a = e.getAsJsonObject();
        if ("PodIP".equals(string(a, "type"))) {
          return string(a, "address");
        }
      }
    }
    return null;
  }

  private static int port(JsonObject status) {
    JsonArray ports = status.getAsJsonArray("ports");
    if (ports != null && !ports.isEmpty()) {
      JsonObject first = ports.get(0).getAsJsonObject();
      if (first.has("port")) {
        return first.get("port").getAsInt();
      }
    }
    return DEFAULT_PORT;
  }

  private static String string(JsonObject o, String key) {
    JsonElement e = o.get(key);
    return e == null || e.isJsonNull() ? null : e.getAsString();
  }
}
