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
 *   <li>{@value #LABEL_SOFT_CAP}：选服时的软上限，没有就用插件的默认值。
 * </ul>
 */
final class Routes {
  static final String LABEL_KIND = "mc.imdomestic.com/kind";
  static final String LABEL_PROTOCOL = "mc.imdomestic.com/protocol";
  static final String LABEL_SOFT_CAP = "mc.imdomestic.com/soft-cap";
  static final String KIND_LOBBY = "lobby";

  /** Reserved 也算：它只是暂时不让 GSA 分配，玩家照样能连。 */
  private static final Set<String> ROUTABLE_STATES = Set.of("Ready", "Allocated", "Reserved");
  private static final int DEFAULT_PORT = 25565;

  record Route(String name, String kind, InetSocketAddress address, int protocol, int softCap) {}

  private final ProxyServer proxy;
  private final Logger logger;
  private final Optional<ViaHook> via;
  private final int defaultSoftCap;
  private final Map<String, Route> routes = new HashMap<>();

  Routes(ProxyServer proxy, Logger logger, Optional<ViaHook> via, int defaultSoftCap) {
    this.proxy = proxy;
    this.logger = logger;
    this.via = via;
    this.defaultSoftCap = defaultSoftCap;
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
   * 动态的大厅（kind=lobby 的 GameServer）优先；没有的话退回 velocity.toml 里 try 列表上的
   * 静态后端，常驻的大厅就是这么接进来的。
   */
  Optional<RegisteredServer> pickLobby(RegisteredServer exclude) {
    return pick(KIND_LOBBY, exclude).or(() -> proxy.getConfiguration().getAttemptConnectionOrder().stream()
        .map(proxy::getServer)
        .flatMap(Optional::stream)
        .filter(s -> exclude == null || !s.getServerInfo().equals(exclude.getServerInfo()))
        .findFirst());
  }

  /**
   * 选一台指定类型的服：优先人最多、但还没到软上限的那台，把人往少数几台上集中，空出来的
   * 才能被 Fleet 缩容回收；都满了就挑人最少的。
   */
  synchronized Optional<RegisteredServer> pick(String kind, RegisteredServer exclude) {
    record Candidate(RegisteredServer server, int players, int softCap) {}
    List<Candidate> candidates = routes.values().stream()
        .filter(r -> kind.equals(r.kind()))
        .flatMap(r -> proxy.getServer(r.name()).stream()
            .map(s -> new Candidate(s, s.getPlayersConnected().size(), r.softCap() > 0 ? r.softCap() : defaultSoftCap)))
        .filter(c -> exclude == null || !c.server().getServerInfo().equals(exclude.getServerInfo()))
        .sorted(Comparator.comparingInt(Candidate::players).reversed()
            .thenComparing(c -> c.server().getServerInfo().getName()))
        .toList();
    return candidates.stream()
        .filter(c -> c.players() < c.softCap())
        .findFirst()
        .or(() -> candidates.stream().min(Comparator.comparingInt(Candidate::players)))
        .map(Candidate::server);
  }

  /** 现在有可用服务器的类型，给 /play 补全用。 */
  synchronized Set<String> kinds() {
    Set<String> kinds = new java.util.TreeSet<>();
    for (Route r : routes.values()) {
      if (r.kind() != null) {
        kinds.add(r.kind());
      }
    }
    return kinds;
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
    String softCap = labels == null ? null : string(labels, LABEL_SOFT_CAP);
    return Optional.of(new Route(name(gs), kind, new InetSocketAddress(address, port(status)),
        protocol == null ? -1 : Integer.parseInt(protocol),
        softCap == null ? -1 : Integer.parseInt(softCap)));
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
