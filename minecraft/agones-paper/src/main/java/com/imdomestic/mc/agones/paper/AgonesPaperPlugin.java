package com.imdomestic.mc.agones.paper;

import com.imdomestic.mc.agones.AgonesSdk;
import com.imdomestic.mc.agones.Lifecycle;
import java.time.Instant;
import java.util.Optional;
import java.util.logging.Logger;
import org.bukkit.Bukkit;
import org.bukkit.World;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.server.ServerLoadEvent;
import org.bukkit.plugin.java.JavaPlugin;

/** 把 Paper 的生命周期接到 {@link Lifecycle} 上；不在 Agones 下运行时什么都不做。 */
public final class AgonesPaperPlugin extends JavaPlugin implements Listener {
  private Lifecycle lifecycle;

  @Override
  public void onEnable() {
    Optional<AgonesSdk> sdk = AgonesSdk.fromEnvironment();
    if (sdk.isEmpty()) {
      getLogger().info("没有 AGONES_SDK_HTTP_PORT，不在 Agones 下运行，插件不做任何事");
      return;
    }
    lifecycle = new Lifecycle(sdk.get(), Lifecycle.Settings.fromEnvironment(), new Lifecycle.Platform() {
      @Override
      public int onlinePlayers() {
        return Bukkit.getOnlinePlayers().size();
      }

      @Override
      public void saveAll() {
        Bukkit.savePlayers();
        for (World world : Bukkit.getWorlds()) {
          world.save();
        }
      }

      @Override
      public Logger logger() {
        return getLogger();
      }
    });
    lifecycle.startStartupPings();
    getServer().getPluginManager().registerEvents(this, this);
    // 每秒一次，在主线程上：主线程卡住时 health ping 也会停。
    getServer().getScheduler().runTaskTimer(this, () -> lifecycle.tick(Instant.now()), 20L, 20L);
  }

  @Override
  public void onDisable() {
    if (lifecycle != null) {
      lifecycle.close();
    }
  }

  @EventHandler
  public void onServerLoad(ServerLoadEvent event) {
    if (event.getType() == ServerLoadEvent.LoadType.STARTUP) {
      lifecycle.serverStarted();
    }
  }

  @EventHandler(priority = EventPriority.MONITOR)
  public void onJoin(PlayerJoinEvent event) {
    lifecycle.playerJoined(event.getPlayer().getUniqueId());
  }

  @EventHandler(priority = EventPriority.MONITOR)
  public void onQuit(PlayerQuitEvent event) {
    lifecycle.playerLeft(event.getPlayer().getUniqueId());
  }
}
