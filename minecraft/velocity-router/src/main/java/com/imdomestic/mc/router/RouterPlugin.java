package com.imdomestic.mc.router;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.KickedFromServerEvent;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import java.util.List;
import java.util.Optional;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

/**
 * 运营网络的路由：把 Agones GameServer 动态注册成 Velocity 后端，进服和被踢时选大厅，
 * 提供 /lobby 和 /play &lt;类型&gt;。见 docs/minecraft-network-todo.md。
 */
@Plugin(
    id = "router",
    name = "Router",
    version = "0.1.0",
    description = "按 Agones GameServer 动态注册后端并选大厅",
    dependencies = {@Dependency(id = "viaversion", optional = true)})
public final class RouterPlugin {
  private final ProxyServer proxy;
  private final Logger logger;
  private Routes routes;
  private GameServerWatcher watcher;

  @Inject
  public RouterPlugin(ProxyServer proxy, Logger logger) {
    this.proxy = proxy;
    this.logger = logger;
  }

  @Subscribe
  public void onInit(ProxyInitializeEvent event) throws Exception {
    routes = new Routes(proxy, logger, ViaHook.create(proxy), envInt("ROUTER_DEFAULT_SOFT_CAP", 40));

    Optional<KubeClient> kube = KubeClient.inCluster();
    if (kube.isPresent()) {
      String namespace = Optional.ofNullable(System.getenv("ROUTER_NAMESPACE")).orElse(KubeClient.podNamespace());
      watcher = new GameServerWatcher(kube.get(), namespace, routes, logger);
      Thread thread = new Thread(watcher, "router-gameserver-watch");
      thread.setDaemon(true);
      thread.start();
      logger.info("开始监听命名空间 {} 里的 GameServer", namespace);
    } else {
      logger.warn("不在集群里运行，只用 velocity.toml 里的静态后端");
    }

    CommandMeta meta = proxy.getCommandManager().metaBuilder("lobby").aliases("hub").plugin(this).build();
    proxy.getCommandManager().register(meta, (SimpleCommand) invocation -> {
      if (!(invocation.source() instanceof Player player)) {
        return;
      }
      RegisteredServer current = player.getCurrentServer().map(c -> c.getServer()).orElse(null);
      routes.pickLobby(current).ifPresentOrElse(
          lobby -> player.createConnectionRequest(lobby).fireAndForget(),
          () -> player.sendMessage(Component.text("现在没有可用的大厅", NamedTextColor.RED)));
    });

    // 没有匹配服务之前的入口：按类型把人往同一台房间里集中。
    proxy.getCommandManager().register(
        proxy.getCommandManager().metaBuilder("play").plugin(this).build(), new SimpleCommand() {
          @Override
          public void execute(Invocation invocation) {
            if (!(invocation.source() instanceof Player player)) {
              return;
            }
            String[] args = invocation.arguments();
            if (args.length != 1 || Routes.KIND_LOBBY.equals(args[0])) {
              player.sendMessage(Component.text("用法：/play <" + String.join("|", playableKinds()) + ">",
                  NamedTextColor.YELLOW));
              return;
            }
            RegisteredServer current = player.getCurrentServer().map(c -> c.getServer()).orElse(null);
            routes.pick(args[0], current).ifPresentOrElse(
                server -> player.createConnectionRequest(server).fireAndForget(),
                () -> player.sendMessage(Component.text("现在没有可用的 " + args[0] + " 房间", NamedTextColor.RED)));
          }

          @Override
          public List<String> suggest(Invocation invocation) {
            String prefix = invocation.arguments().length == 0 ? "" : invocation.arguments()[0];
            return playableKinds().stream().filter(k -> k.startsWith(prefix)).toList();
          }
        });
  }

  private List<String> playableKinds() {
    return routes.kinds().stream().filter(k -> !Routes.KIND_LOBBY.equals(k)).toList();
  }

  @Subscribe
  public void onShutdown(ProxyShutdownEvent event) {
    if (watcher != null) {
      watcher.stop();
    }
  }

  @Subscribe
  public void onChooseInitialServer(PlayerChooseInitialServerEvent event) {
    routes.pickLobby(null).ifPresent(event::setInitialServer);
  }

  /** 被任何后端踢出（包括大厅关服）时，送去另一个大厅；没有大厅就按 Velocity 默认处理。 */
  @Subscribe
  public void onKicked(KickedFromServerEvent event) {
    routes.pickLobby(event.getServer()).ifPresent(lobby -> {
      Component reason = event.getServerKickReason().orElse(Component.text("连接断开"));
      event.setResult(KickedFromServerEvent.RedirectPlayer.create(lobby, reason));
    });
  }

  private static int envInt(String name, int fallback) {
    String value = System.getenv(name);
    return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
  }
}
