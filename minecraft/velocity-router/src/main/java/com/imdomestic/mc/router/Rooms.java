package com.imdomestic.mc.router;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

/**
 * 房间：开房间、按房间码加入、快速加入、邀请、关房。
 *
 * <p>开房间就是创建一个 GameServerAllocation：Agones 原子地从对应 Fleet 里挑一台 Ready 的服
 * 标成 Allocated，同时写上房间码、可见性和房主。之后谁在什么房间、房间是谁的，都从
 * GameServer 上读（{@link Routes}），插件只在内存里记还在等分配的请求。
 *
 * <p>队长进了房间，队员跟着进（{@link Parties}）；/play 找房间时按整队的人数留位置。
 */
final class Rooms {
  private static final String CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  private static final int CODE_LENGTH = 4;
  /** 没有空闲的服时一直重试，FleetAutoscaler 会补；bingo 冷启动大约 5 分钟。 */
  private static final Duration WAIT = Duration.ofMinutes(6);
  private static final long RETRY_SECONDS = 5;
  private static final Duration CLOSING_MEMORY = Duration.ofMinutes(2);

  private final ProxyServer proxy;
  private final Object plugin;
  private final Routes routes;
  private final Parties parties;
  private final Optional<KubeClient> kube;
  private final String namespace;
  private final Logger logger;
  private final SecureRandom random = new SecureRandom();
  private final Map<UUID, ScheduledTask> pending = new ConcurrentHashMap<>();
  /** 被房主关掉的房间：后端名 → 关闭时间，用来把踢人提示换成"房间已关闭"。 */
  private final Map<String, Instant> closing = new ConcurrentHashMap<>();

  Rooms(ProxyServer proxy, Object plugin, Routes routes, Parties parties, Optional<KubeClient> kube,
      String namespace, Logger logger) {
    this.proxy = proxy;
    this.plugin = plugin;
    this.routes = routes;
    this.parties = parties;
    this.kube = kube;
    this.namespace = namespace;
    this.logger = logger;
  }

  /**
   * 进同类型里最满、还在等人、装得下整队的公开房间；没有就开一个公开房间。队员不用管：
   * 队长连上房间时 {@link #onConnected} 会把他们带过去。
   */
  void play(Player player, String kind) {
    if (!checkKind(player, kind)) {
      return;
    }
    int slots = 1 + parties.followers(player).size();
    routes.quickJoin(kind, currentServer(player), slots).ifPresentOrElse(
        server -> player.createConnectionRequest(server).fireAndForget(),
        () -> allocate(player, kind, true));
  }

  void create(Player player, String kind, boolean isPublic) {
    if (checkKind(player, kind)) {
      allocate(player, kind, isPublic);
    }
  }

  void join(Player player, String code) {
    Optional<Routes.Route> room = routes.room(code);
    Optional<RegisteredServer> server = room.flatMap(routes::server);
    if (server.isEmpty()) {
      player.sendMessage(Component.text("没有房间 " + code.toUpperCase(java.util.Locale.ROOT), NamedTextColor.RED));
      return;
    }
    if (isOn(player, server.get())) {
      player.sendMessage(Component.text("你已经在这个房间里了", NamedTextColor.YELLOW));
      return;
    }
    player.createConnectionRequest(server.get()).fireAndForget();
  }

  void list(CommandSource source, String kind) {
    List<Routes.Route> rooms = routes.publicRooms(kind);
    if (rooms.isEmpty()) {
      source.sendMessage(Component.text("现在没有公开房间。用 /room create <类型> 开一个。", NamedTextColor.YELLOW));
      return;
    }
    source.sendMessage(Component.text("公开房间（点击加入）：", NamedTextColor.GOLD));
    for (Routes.Route r : rooms) {
      String line = String.format("  %s  %s  %d/%d  %s  房主 %s", r.room(), r.kind(), routes.players(r),
          routes.softCap(r), r.phaseText(), r.ownerName() == null ? "-" : r.ownerName());
      source.sendMessage(Component.text(line, NamedTextColor.WHITE)
          .clickEvent(ClickEvent.runCommand("/room join " + r.room()))
          .hoverEvent(HoverEvent.showText(Component.text("加入房间 " + r.room()))));
    }
  }

  void info(Player player) {
    Optional<Routes.Route> room = currentRoom(player);
    if (room.isEmpty()) {
      player.sendMessage(Component.text("你现在不在房间里", NamedTextColor.YELLOW));
      return;
    }
    Routes.Route r = room.get();
    player.sendMessage(Component.text(String.format("房间 %s：%s，%s，%d/%d 人，%s，房主 %s",
        r.room(), r.kind(), r.isPublic() ? "公开" : "私有", routes.players(r), routes.softCap(r),
        r.phase() == null ? "-" : r.phaseText(), r.ownerName() == null ? "-" : r.ownerName()), NamedTextColor.AQUA));
  }

  void invite(Player player, String targetName) {
    Optional<Routes.Route> room = currentRoom(player);
    if (room.isEmpty()) {
      player.sendMessage(Component.text("先进一个房间再邀请别人", NamedTextColor.RED));
      return;
    }
    Optional<Player> target = proxy.getPlayer(targetName);
    if (target.isEmpty()) {
      player.sendMessage(Component.text(targetName + " 不在线", NamedTextColor.RED));
      return;
    }
    String code = room.get().room();
    target.get().sendMessage(Component.text(player.getUsername() + " 邀请你加入房间 " + code
            + "（" + room.get().kind() + "）", NamedTextColor.AQUA)
        .append(Component.text(" [点击加入]", NamedTextColor.GREEN)
            .clickEvent(ClickEvent.runCommand("/room join " + code))
            .hoverEvent(HoverEvent.showText(Component.text("/room join " + code)))));
    player.sendMessage(Component.text("已邀请 " + target.get().getUsername(), NamedTextColor.GREEN));
  }

  /** 房主关房：删掉 GameServer，里面的人会被踢出，再由路由插件送回大厅。 */
  void close(Player player) {
    Optional<Routes.Route> room = currentRoom(player);
    if (room.isEmpty()) {
      player.sendMessage(Component.text("你现在不在房间里", NamedTextColor.RED));
      return;
    }
    Routes.Route r = room.get();
    if (!player.getUniqueId().toString().equals(r.ownerId())) {
      player.sendMessage(Component.text("只有房主（" + r.ownerName() + "）能关这个房间", NamedTextColor.RED));
      return;
    }
    if (kube.isEmpty()) {
      player.sendMessage(Component.text("这个代理不在集群里，不能关房间", NamedTextColor.RED));
      return;
    }
    closing.put(r.name(), Instant.now());
    proxy.getScheduler().buildTask(plugin, () -> {
      try {
        kube.get().delete("/apis/agones.dev/v1/namespaces/" + namespace + "/gameservers/" + r.name());
        logger.info("{} 关闭了房间 {}（{}）", player.getUsername(), r.room(), r.name());
      } catch (Exception e) {
        closing.remove(r.name());
        logger.warn("关闭房间 {} 失败：{}", r.room(), e.toString());
        player.sendMessage(Component.text("关房间失败：" + e.getMessage(), NamedTextColor.RED));
      }
    }).schedule();
  }

  /** 被踢出时的提示：房主关的房间换成明确的说法，其他情况沿用后端给的原因。 */
  Component kickReason(RegisteredServer server, Optional<Component> original) {
    Instant closedAt = closing.get(server.getServerInfo().getName());
    if (closedAt != null && Duration.between(closedAt, Instant.now()).compareTo(CLOSING_MEMORY) < 0) {
      return Component.text("房间已被房主关闭，已送回大厅", NamedTextColor.YELLOW);
    }
    closing.entrySet().removeIf(e -> Duration.between(e.getValue(), Instant.now()).compareTo(CLOSING_MEMORY) > 0);
    return original.orElse(Component.text("连接断开", NamedTextColor.YELLOW));
  }

  /** 进入房间时告诉玩家房间码和常用命令；进房间的是队长的话，把队员也带进来。 */
  void onConnected(Player player, RegisteredServer server) {
    Optional<Routes.Route> room = routes.routeOf(server).filter(Routes.Route::isRoom);
    if (room.isEmpty()) {
      return;
    }
    Routes.Route r = room.get();
    player.sendMessage(Component.text("你进入了房间 " + r.room() + "（" + r.kind() + "，" + (r.isPublic() ? "公开" : "私有")
            + "，房主 " + (r.ownerName() == null ? "-" : r.ownerName()) + "）。", NamedTextColor.AQUA)
        .append(Component.text(" /room invite <玩家> 邀请朋友，/lobby 回大厅", NamedTextColor.GRAY)));
    pull(player, parties.followers(player), server, "房间 " + r.room());
  }

  /** /party warp：把队员都拉到队长现在所在的服，大厅也行。 */
  void warpParty(Player leader) {
    if (!parties.isLeader(leader)) {
      leader.sendMessage(Component.text("只有队长能召集队员", NamedTextColor.RED));
      return;
    }
    RegisteredServer server = currentServer(leader);
    if (server == null) {
      return;
    }
    List<Player> moved = pull(leader, parties.followers(leader), server, where(server));
    leader.sendMessage(Component.text(moved.isEmpty() ? "队员都已经在这里了" : "已召集 " + moved.size() + " 名队员",
        NamedTextColor.GREEN));
  }

  /** 刚入队的人：队长在房间里的话直接带进去。 */
  void joinLeader(Player member, Player leader) {
    RegisteredServer server = currentServer(leader);
    routes.routeOf(server).filter(Routes.Route::isRoom)
        .ifPresent(r -> pull(leader, List.of(member), server, "房间 " + r.room()));
  }

  private List<Player> pull(Player leader, List<Player> members, RegisteredServer server, String where) {
    List<Player> moved = members.stream().filter(m -> !isOn(m, server)).toList();
    for (Player member : moved) {
      cancelPending(member);
      member.sendMessage(Component.text("跟着队长 " + leader.getUsername() + " 去" + where, NamedTextColor.GRAY));
      member.createConnectionRequest(server).fireAndForget();
    }
    return moved;
  }

  private String where(RegisteredServer server) {
    return routes.routeOf(server)
        .map(r -> r.isRoom() ? "房间 " + r.room() : r.kind())
        .orElse(server.getServerInfo().getName());
  }

  void cancelPending(Player player) {
    ScheduledTask task = pending.remove(player.getUniqueId());
    if (task != null) {
      task.cancel();
    }
  }

  Set<String> kinds() {
    return routes.roomKinds();
  }

  Set<String> codes() {
    return routes.roomCodes();
  }

  private boolean checkKind(Player player, String kind) {
    if (routes.roomKinds().contains(kind)) {
      return true;
    }
    player.sendMessage(Component.text("没有 " + kind + " 这种房间，可选：" + String.join("、", routes.roomKinds()),
        NamedTextColor.RED));
    return false;
  }

  /** 每 5 秒发一次分配请求，直到分到一台或者超时；同一个人重新开房会取消上一个请求。 */
  private void allocate(Player player, String kind, boolean isPublic) {
    if (kube.isEmpty()) {
      player.sendMessage(Component.text("这个代理不在集群里，不能开房间", NamedTextColor.RED));
      return;
    }
    cancelPending(player);
    Instant started = Instant.now();
    AtomicBoolean inFlight = new AtomicBoolean();
    player.sendMessage(Component.text("正在开 " + kind + " 房间…", NamedTextColor.GRAY));
    Consumer<ScheduledTask> attempt = task -> {
      // 第一次执行可能早于下面的 pending.put，所以这里不比对 pending；被新请求顶掉时由
      // cancelPending 取消这个任务。
      if (!player.isActive()) {
        pending.remove(player.getUniqueId(), task);
        task.cancel();
        return;
      }
      long waited = Duration.between(started, Instant.now()).toSeconds();
      if (waited > WAIT.toSeconds()) {
        pending.remove(player.getUniqueId(), task);
        task.cancel();
        player.sendMessage(Component.text("等了 " + WAIT.toMinutes() + " 分钟还没有空闲的 " + kind
            + " 服务器，稍后再试", NamedTextColor.RED));
        return;
      }
      if (!inFlight.compareAndSet(false, true)) {
        return;
      }
      try {
        String code = newCode();
        JsonObject status = kube.get()
            .post("/apis/allocation.agones.dev/v1/namespaces/" + namespace + "/gameserverallocations",
                allocation(kind, code, isPublic, player))
            .getAsJsonObject("status");
        if ("Allocated".equals(status.get("state").getAsString())) {
          pending.remove(player.getUniqueId(), task);
          task.cancel();
          String server = status.get("gameServerName").getAsString();
          logger.info("{} 开了 {} 房间 {}（{}，{}）", player.getUsername(), kind, code, server, isPublic ? "公开" : "私有");
          player.sendMessage(Component.text("房间 " + code + " 已开好（" + kind + "，" + (isPublic ? "公开" : "私有")
              + "），朋友可以用 /room join " + code + " 加入", NamedTextColor.GREEN));
          connectWhenRegistered(player, server, 0);
        } else {
          player.sendActionBar(Component.text("正在准备 " + kind + " 房间…已等 " + waited + " 秒", NamedTextColor.GRAY));
        }
      } catch (Exception e) {
        logger.warn("给 {} 分配 {} 房间失败：{}", player.getUsername(), kind, e.toString());
      } finally {
        inFlight.set(false);
      }
    };
    pending.put(player.getUniqueId(), proxy.getScheduler().buildTask(plugin, attempt)
        .repeat(RETRY_SECONDS, TimeUnit.SECONDS).schedule());
  }

  /** 分到的服原本是 Ready 的待命服，一般已经注册过；以防万一等它出现。 */
  private void connectWhenRegistered(Player player, String server, int tries) {
    Optional<RegisteredServer> registered = proxy.getServer(server);
    if (registered.isPresent()) {
      player.createConnectionRequest(registered.get()).fireAndForget();
    } else if (tries < 20 && player.isActive()) {
      proxy.getScheduler().buildTask(plugin, () -> connectWhenRegistered(player, server, tries + 1))
          .delay(500, TimeUnit.MILLISECONDS).schedule();
    } else {
      player.sendMessage(Component.text("房间开好了，但暂时连不上，稍后用 /room join 再试", NamedTextColor.RED));
    }
  }

  private JsonObject allocation(String kind, String code, boolean isPublic, Player owner) {
    JsonObject matchLabels = new JsonObject();
    matchLabels.addProperty(Routes.LABEL_KIND, kind);
    JsonObject selector = new JsonObject();
    selector.add("matchLabels", matchLabels);
    selector.addProperty("gameServerState", "Ready");
    JsonArray selectors = new JsonArray();
    selectors.add(selector);

    JsonObject labels = new JsonObject();
    labels.addProperty(Routes.LABEL_ROOM, code);
    labels.addProperty(Routes.LABEL_VISIBILITY, isPublic ? "public" : "private");
    JsonObject annotations = new JsonObject();
    annotations.addProperty(Routes.ANNOTATION_OWNER, owner.getUniqueId().toString());
    annotations.addProperty(Routes.ANNOTATION_OWNER_NAME, owner.getUsername());
    JsonObject metadata = new JsonObject();
    metadata.add("labels", labels);
    metadata.add("annotations", annotations);

    JsonObject spec = new JsonObject();
    spec.add("selectors", selectors);
    spec.add("metadata", metadata);
    JsonObject body = new JsonObject();
    body.addProperty("apiVersion", "allocation.agones.dev/v1");
    body.addProperty("kind", "GameServerAllocation");
    body.add("spec", spec);
    return body;
  }

  /** 4 位，去掉了 I/O/0/1 这种容易看错的字符；和现有房间撞了就重来。 */
  private String newCode() {
    Set<String> used = routes.roomCodes();
    while (true) {
      StringBuilder code = new StringBuilder(CODE_LENGTH);
      for (int i = 0; i < CODE_LENGTH; i++) {
        code.append(CODE_ALPHABET.charAt(random.nextInt(CODE_ALPHABET.length())));
      }
      if (!used.contains(code.toString())) {
        return code.toString();
      }
    }
  }

  private Optional<Routes.Route> currentRoom(Player player) {
    return routes.routeOf(currentServer(player)).filter(Routes.Route::isRoom);
  }

  private static RegisteredServer currentServer(Player player) {
    return player.getCurrentServer().map(c -> c.getServer()).orElse(null);
  }

  /** 按 ServerInfo 比：后端重新注册后是另一个对象。 */
  private static boolean isOn(Player player, RegisteredServer server) {
    RegisteredServer current = currentServer(player);
    return current != null && current.getServerInfo().equals(server.getServerInfo());
  }
}
