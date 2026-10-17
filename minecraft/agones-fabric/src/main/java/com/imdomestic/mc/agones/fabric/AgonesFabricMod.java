package com.imdomestic.mc.agones.fabric;

import com.imdomestic.mc.agones.AgonesSdk;
import com.imdomestic.mc.agones.Lifecycle;
import java.time.Instant;
import java.util.Optional;
import java.util.logging.Logger;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.minecraft.server.MinecraftServer;

/** 把 Fabric 服务端的生命周期接到 {@link Lifecycle} 上；不在 Agones 下运行时什么都不做。 */
public final class AgonesFabricMod implements DedicatedServerModInitializer {
  private static final Logger LOG = Logger.getLogger("AgonesBridge");

  private Lifecycle lifecycle;
  private MinecraftServer server;
  private int ticks;

  @Override
  public void onInitializeServer() {
    Optional<AgonesSdk> sdk = AgonesSdk.fromEnvironment();
    if (sdk.isEmpty()) {
      LOG.info("没有 AGONES_SDK_HTTP_PORT，不在 Agones 下运行，mod 不做任何事");
      return;
    }
    Optional<BingoPhase> bingo = BingoPhase.detect(LOG);
    lifecycle = new Lifecycle(sdk.get(), Lifecycle.Settings.fromEnvironment(), new Lifecycle.Platform() {
      @Override
      public int onlinePlayers() {
        return server == null ? 0 : server.getPlayerCount();
      }

      @Override
      public void saveAll() {
        server.getPlayerList().saveAll();
        server.saveEverything(false, true, true);
      }

      @Override
      public Logger logger() {
        return LOG;
      }

      @Override
      public String phase() {
        return bingo.map(BingoPhase::current).orElse(null);
      }
    });
    // mod 初始化发生在世界加载之前，从这里开始代 ping，直到主线程开始 tick。
    lifecycle.startStartupPings();

    ServerLifecycleEvents.SERVER_STARTING.register(s -> server = s);
    ServerLifecycleEvents.SERVER_STARTED.register(s -> lifecycle.serverStarted());
    ServerLifecycleEvents.SERVER_STOPPED.register(s -> lifecycle.close());
    // 每 20 tick（正常是一秒）一次，在主线程上：主线程卡住时 health ping 也会停。
    ServerTickEvents.END_SERVER_TICK.register(s -> {
      if (++ticks % 20 == 0) {
        lifecycle.tick(Instant.now());
      }
    });
    ServerPlayConnectionEvents.JOIN.register(
        (handler, sender, s) -> lifecycle.playerJoined(handler.getPlayer().getUUID()));
    ServerPlayConnectionEvents.DISCONNECT.register(
        (handler, s) -> lifecycle.playerLeft(handler.getPlayer().getUUID()));
  }
}
