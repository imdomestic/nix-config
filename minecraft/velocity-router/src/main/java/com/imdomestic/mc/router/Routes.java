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
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;

/**
 * GameServer 到 Velocity 后端的映射，也是房间的登记表。只管理自己注册的后端，velocity.toml
 * 里的静态后端不碰。所有房间信息都来自 GameServer 本身，插件不另存状态。
 *
 * <p>运营网络内部的标签约定（见 docs/minecraft-network-todo.md）：
 * <ul>
 *   <li>{@value #LABEL_KIND}：服务器类型，比如 bingo。没有这个标签的 GameServer 不路由。
 *   <li>{@value #LABEL_PROTOCOL}：后端的协议版本号，告诉 Velocity 上的 Via。
 *   <li>{@value #LABEL_SOFT_CAP}：选服时的软上限，没有就用插件的默认值。
 *   <li>{@value #LABEL_ROOM}、{@value #LABEL_VISIBILITY}：房间码和 public/private，开房间时写入。
 *   <li>注解 {@value #ANNOTATION_OWNER}、{@value #ANNOTATION_OWNER_NAME}：房主的 UUID 和名字。
 *   <li>{@value #LABEL_PHASE}：对局阶段（waiting、starting、playing、ended），由服务器上的
 *       agones-core 通过 SDK 写入。没有这个标签的服当作一直在等人。
 * </ul>
 */
final class Routes {
  static final String LABEL_KIND = "mc.imdomestic.com/kind";
  static final String LABEL_PROTOCOL = "mc.imdomestic.com/protocol";
  static final String LABEL_SOFT_CAP = "mc.imdomestic.com/soft-cap";
  static final String LABEL_ROOM = "mc.imdomestic.com/room";
  static final String LABEL_VISIBILITY = "mc.imdomestic.com/visibility";
  static final String ANNOTATION_OWNER = "mc.imdomestic.com/owner";
  static final String ANNOTATION_OWNER_NAME = "mc.imdomestic.com/owner-name";
  static final String LABEL_PHASE = "agones.dev/sdk-phase";
  static final String PHASE_WAITING = "waiting";
  static final String KIND_LOBBY = "lobby";

  /** Reserved 也算：它只是暂时不让 GSA 分配，玩家照样能连。 */
  private static final Set<String> ROUTABLE_STATES = Set.of("Ready", "Allocated", "Reserved");
  private static final int DEFAULT_PORT = 25565;

  /** 一台后端。room 为 null 的是还没被开成房间的待命服（或者大厅）。 */
  record Route(
      String name,
      String kind,
      InetSocketAddress address,
      int protocol,
      int softCap,
      String state,
      String room,
      boolean isPublic,
      String ownerId,
      String ownerName,
      String phase) {

    boolean isRoom() {
      return room != null && "Allocated".equals(state);
    }

    /** 快速加入只进还在等人的房间；已经开打的房间只能凭房间码进。 */
    boolean isWaiting() {
      return phase == null || PHASE_WAITING.equals(phase);
    }

    String phaseText() {
      return phase == null ? "" : switch (phase) {
        case "waiting" -> "等待中";
        case "starting" -> "即将开始";
        case "playing" -> "游戏中";
        case "ended" -> "已结束";
        default -> phase;
      };
    }
  }

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
    Route next = wanted.get();
    // 地址没变就只更新登记信息（状态、房间码……）。重新注册会换掉 Velocity 里的后端对象，
    // 已经连在上面的玩家就不算在新对象的人数里了。
    if (current != null && current.address().equals(next.address())) {
      if (next.protocol() != current.protocol() && next.protocol() > 0) {
        via.ifPresent(v -> v.setProtocol(name, next.protocol()));
      }
      routes.put(name, next);
      return;
    }
    if (current != null) {
      unregister(current);
    }
    register(next);
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
  synchronized Optional<RegisteredServer> pickLobby(RegisteredServer exclude) {
    Comparator<RegisteredServer> byPlayers = Comparator.comparingInt(s -> s.getPlayersConnected().size());
    return routes.values().stream()
        .filter(r -> KIND_LOBBY.equals(r.kind()))
        .flatMap(r -> server(r).stream())
        .filter(s -> !same(s, exclude))
        .min(byPlayers)
        .or(() -> proxy.getConfiguration().getAttemptConnectionOrder().stream()
            .map(proxy::getServer)
            .flatMap(Optional::stream)
            .filter(s -> !same(s, exclude))
            .findFirst());
  }

  /**
   * /play 用：同类型里最满、还在等人、并且再进 slots 个人也不超过软上限的公开房间。只挑已经
   * 开成房间的，待命的空服要经过分配（带上房间码）才会被用到。
   */
  synchronized Optional<RegisteredServer> quickJoin(String kind, RegisteredServer exclude, int slots) {
    return routes.values().stream()
        .filter(r -> kind.equals(r.kind()) && r.isRoom() && r.isPublic() && r.isWaiting())
        .flatMap(r -> server(r).stream()
            .filter(s -> !same(s, exclude))
            .filter(s -> s.getPlayersConnected().size() + slots <= softCap(r)))
        .max(Comparator.<RegisteredServer>comparingInt(s -> s.getPlayersConnected().size())
            .thenComparing(s -> s.getServerInfo().getName(), Comparator.reverseOrder()));
  }

  synchronized Optional<Route> room(String code) {
    String wanted = code.toUpperCase(Locale.ROOT);
    return routes.values().stream().filter(r -> r.isRoom() && wanted.equals(r.room())).findFirst();
  }

  synchronized Optional<Route> routeOf(RegisteredServer server) {
    return server == null ? Optional.empty() : Optional.ofNullable(routes.get(server.getServerInfo().getName()));
  }

  /** 给玩家看的位置：大厅、bingo 房间 4M5C，或者后端名。 */
  synchronized String describe(RegisteredServer server) {
    Optional<Route> route = routeOf(server);
    if (route.isPresent() && route.get().isRoom()) {
      return route.get().kind() + " 房间 " + route.get().room();
    }
    String kind = route.map(Route::kind).orElse(server.getServerInfo().getName());
    return KIND_LOBBY.equals(kind) ? "大厅" : kind;
  }

  synchronized List<Route> publicRooms(String kind) {
    return rooms().stream().filter(r -> r.isPublic() && (kind == null || kind.equals(r.kind()))).toList();
  }

  /** 所有房间，包括私有的。 */
  synchronized List<Route> rooms() {
    return routes.values().stream()
        .filter(Route::isRoom)
        .sorted(Comparator.comparing(Route::kind).thenComparing(Route::room))
        .toList();
  }

  synchronized Set<String> roomCodes() {
    Set<String> codes = new TreeSet<>();
    for (Route r : routes.values()) {
      if (r.isRoom()) {
        codes.add(r.room());
      }
    }
    return codes;
  }

  /** 能开房间的类型：有 GameServer 的类型，大厅除外。 */
  synchronized Set<String> roomKinds() {
    Set<String> kinds = new TreeSet<>();
    for (Route r : routes.values()) {
      if (r.kind() != null && !KIND_LOBBY.equals(r.kind())) {
        kinds.add(r.kind());
      }
    }
    return kinds;
  }

  int players(Route route) {
    return server(route).map(s -> s.getPlayersConnected().size()).orElse(0);
  }

  int softCap(Route route) {
    return route.softCap() > 0 ? route.softCap() : defaultSoftCap;
  }

  Optional<RegisteredServer> server(Route route) {
    return proxy.getServer(route.name());
  }

  private static boolean same(RegisteredServer a, RegisteredServer b) {
    return b != null && a.getServerInfo().equals(b.getServerInfo());
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
    JsonObject labels = metadata.has("labels") ? metadata.getAsJsonObject("labels") : new JsonObject();
    JsonObject annotations = metadata.has("annotations") ? metadata.getAsJsonObject("annotations") : new JsonObject();
    String protocol = string(labels, LABEL_PROTOCOL);
    String softCap = string(labels, LABEL_SOFT_CAP);
    return Optional.of(new Route(
        name(gs),
        string(labels, LABEL_KIND),
        new InetSocketAddress(address, port(status)),
        protocol == null ? -1 : Integer.parseInt(protocol),
        softCap == null ? -1 : Integer.parseInt(softCap),
        state,
        string(labels, LABEL_ROOM),
        !"private".equals(string(labels, LABEL_VISIBILITY)),
        string(annotations, ANNOTATION_OWNER),
        string(annotations, ANNOTATION_OWNER_NAME),
        string(labels, LABEL_PHASE)));
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
