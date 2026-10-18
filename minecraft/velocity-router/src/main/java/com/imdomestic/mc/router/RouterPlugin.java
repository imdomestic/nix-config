package com.imdomestic.mc.router;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.player.KickedFromServerEvent;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

/**
 * 运营网络的路由：把 Agones GameServer 动态注册成 Velocity 后端，进服和被踢时选大厅，
 * 提供 /lobby、/play、/room 和 /party，以及给 QQ bot 读的状态接口。见 docs/minecraft-network-todo.md。
 */
@Plugin(
    id = "router",
    name = "Router",
    version = "0.3.0",
    description = "按 Agones GameServer 动态注册后端，开房间、匹配和组队",
    dependencies = {@Dependency(id = "viaversion", optional = true)})
public final class RouterPlugin {
  private final ProxyServer proxy;
  private final Logger logger;
  private Routes routes;
  private Rooms rooms;
  private Parties parties;
  private GameServerWatcher watcher;
  private StatusServer status;

  @Inject
  public RouterPlugin(ProxyServer proxy, Logger logger) {
    this.proxy = proxy;
    this.logger = logger;
  }

  @Subscribe
  public void onInit(ProxyInitializeEvent event) throws Exception {
    Optional<ViaHook> via = ViaHook.create(proxy);
    routes = new Routes(proxy, logger, via, envInt("ROUTER_DEFAULT_SOFT_CAP", 40));
    // velocity.toml 里静态后端的版本，格式 "lobby=767,foo=774"。不告诉的话 Via 要等启动后第一轮
    // 探测才知道，在那之前按最低版本翻译，代理每次重启后的头一分钟谁都进不了大厅。
    via.ifPresent(v -> staticProtocols().forEach((server, protocol) -> {
      v.setProtocol(server, protocol);
      logger.info("告诉 Via：{} 是协议 {}", server, protocol);
    }));

    Optional<KubeClient> kube = KubeClient.inCluster();
    String namespace = Optional.ofNullable(System.getenv("ROUTER_NAMESPACE"))
        .orElseGet(() -> kube.isPresent() ? podNamespace() : "default");
    if (kube.isPresent()) {
      watcher = new GameServerWatcher(kube.get(), namespace, routes, logger);
      Thread thread = new Thread(watcher, "router-gameserver-watch");
      thread.setDaemon(true);
      thread.start();
      logger.info("开始监听命名空间 {} 里的 GameServer", namespace);
    } else {
      logger.warn("不在集群里运行，只用 velocity.toml 里的静态后端，不能开房间");
    }
    parties = new Parties(proxy, routes);
    rooms = new Rooms(proxy, this, routes, parties, kube, namespace, logger);

    // 0 表示不开。
    int statusPort = envInt("ROUTER_STATUS_PORT", 8080);
    if (statusPort > 0) {
      status = StatusServer.start(statusPort, proxy, routes, logger);
    }

    CommandManager commands = proxy.getCommandManager();
    commands.register(commands.metaBuilder("lobby").aliases("hub").plugin(this).build(), (SimpleCommand) invocation -> {
      if (!(invocation.source() instanceof Player player)) {
        return;
      }
      routes.pickLobby(currentServer(player)).ifPresentOrElse(
          lobby -> player.createConnectionRequest(lobby).fireAndForget(),
          () -> player.sendMessage(Component.text("现在没有可用的大厅", NamedTextColor.RED)));
    });

    commands.register(commands.metaBuilder("play").plugin(this).build(), new SimpleCommand() {
      @Override
      public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
          return;
        }
        String[] args = invocation.arguments();
        if (args.length != 1) {
          player.sendMessage(Component.text("用法：/play <" + String.join("|", rooms.kinds()) + ">",
              NamedTextColor.YELLOW));
          return;
        }
        rooms.play(player, args[0].toLowerCase(Locale.ROOT));
      }

      @Override
      public List<String> suggest(Invocation invocation) {
        String prefix = invocation.arguments().length == 0 ? "" : invocation.arguments()[0];
        return rooms.kinds().stream().filter(k -> k.startsWith(prefix)).toList();
      }
    });

    commands.register(commands.metaBuilder("room").plugin(this).build(), new RoomCommand(proxy, rooms));
    commands.register(commands.metaBuilder("party").aliases("p").plugin(this).build(),
        new PartyCommand(proxy, parties, rooms));
  }

  @Subscribe
  public void onShutdown(ProxyShutdownEvent event) {
    if (watcher != null) {
      watcher.stop();
    }
    if (status != null) {
      status.stop();
    }
  }

  @Subscribe
  public void onChooseInitialServer(PlayerChooseInitialServerEvent event) {
    routes.pickLobby(null).ifPresent(event::setInitialServer);
  }

  @Subscribe
  public void onServerConnected(ServerConnectedEvent event) {
    rooms.onConnected(event.getPlayer(), event.getServer());
  }

  @Subscribe
  public void onDisconnect(DisconnectEvent event) {
    rooms.cancelPending(event.getPlayer());
    parties.disconnected(event.getPlayer());
  }

  /** 被任何后端踢出（包括房间关闭）时，送去另一个大厅；没有大厅就按 Velocity 默认处理。 */
  @Subscribe
  public void onKicked(KickedFromServerEvent event) {
    routes.pickLobby(event.getServer()).ifPresent(lobby -> event.setResult(
        KickedFromServerEvent.RedirectPlayer.create(lobby, rooms.kickReason(event.getServer(), event.getServerKickReason()))));
  }

  private static RegisteredServer currentServer(Player player) {
    return player.getCurrentServer().map(c -> c.getServer()).orElse(null);
  }

  private static String podNamespace() {
    try {
      return KubeClient.podNamespace();
    } catch (java.io.IOException e) {
      return "default";
    }
  }

  private static Map<String, Integer> staticProtocols() {
    Map<String, Integer> protocols = new LinkedHashMap<>();
    String value = System.getenv("ROUTER_STATIC_PROTOCOLS");
    if (value != null) {
      for (String entry : value.split(",")) {
        String[] kv = entry.trim().split("=", 2);
        if (kv.length == 2) {
          protocols.put(kv[0].trim(), Integer.parseInt(kv[1].trim()));
        }
      }
    }
    return protocols;
  }

  private static int envInt(String name, int fallback) {
    String value = System.getenv(name);
    return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
  }
}
