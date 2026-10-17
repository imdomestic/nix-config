package com.imdomestic.mc.agones;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 服务器生命周期和 Agones 状态机之间的映射，和具体平台无关。
 *
 * <p>平台适配层要做三件事：服务器加载完调 {@link #serverStarted()}；在<b>主线程</b>上每秒调一次
 * {@link #tick(Instant)}；玩家进出时调 {@link #playerJoined(UUID)} / {@link #playerLeft(UUID)}。
 *
 * <ul>
 *   <li>Health：每次 tick 都 ping，主线程卡住 ping 就停，Agones 据此判 Unhealthy。
 *       主线程开始 tick 之前由后台线程代 ping，否则加载慢的服会在启动阶段被误杀。
 *   <li>Ready：服务器加载完成后发一次，失败就在下一次 tick 重试。
 *   <li>LOBBY 模式：有人时 Allocate（Fleet 缩容不会删 Allocated 的服），空了一段时间后
 *       Ready（回到可回收的空闲池）。
 *   <li>ROOM 模式：空了一段时间后存盘并 Shutdown。
 * </ul>
 */
public final class Lifecycle implements AutoCloseable {
  public enum Mode {
    LOBBY,
    ROOM;

    static Mode parse(String value) {
      return valueOf(value.trim().toUpperCase(Locale.ROOT));
    }
  }

  public interface Platform {
    int onlinePlayers();

    /** ROOM 模式关服前在主线程上调用。 */
    void saveAll();

    Logger logger();
  }

  public record Settings(Mode mode, Duration idle) {
    /** MC_AGONES_MODE=lobby|room，MC_AGONES_IDLE_SECONDS 默认大厅 30 秒、房间 600 秒。 */
    public static Settings fromEnvironment() {
      String rawMode = System.getenv("MC_AGONES_MODE");
      Mode mode = rawMode == null || rawMode.isBlank() ? Mode.LOBBY : Mode.parse(rawMode);
      String rawIdle = System.getenv("MC_AGONES_IDLE_SECONDS");
      long idle = rawIdle == null || rawIdle.isBlank()
          ? (mode == Mode.LOBBY ? 30 : 600)
          : Long.parseLong(rawIdle.trim());
      return new Settings(mode, Duration.ofSeconds(idle));
    }
  }

  private static final String PLAYERS_LIST = "players";
  private static final Duration RETRY_SHUTDOWN = Duration.ofSeconds(10);

  private final AgonesSdk sdk;
  private final Settings settings;
  private final Platform platform;
  private final Logger log;
  private final ScheduledExecutorService startupPinger;
  private final Map<String, Instant> lastLogged = new HashMap<>();

  private volatile boolean ticking;

  // 以下状态都在 this 上加锁：tick 在主线程，HTTP 回调在 HttpClient 的线程上。
  private boolean started;
  private boolean readyConfirmed;
  private boolean readyInFlight;
  private boolean allocated;
  private boolean transitionInFlight;
  private Instant emptySince;
  private Instant shutdownRequestedAt;

  public Lifecycle(AgonesSdk sdk, Settings settings, Platform platform) {
    this.sdk = sdk;
    this.settings = settings;
    this.platform = platform;
    this.log = platform.logger();
    this.startupPinger = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "agones-startup-health");
      t.setDaemon(true);
      return t;
    });
  }

  public Settings settings() {
    return settings;
  }

  /** 插件一启用就调用：主线程开始 tick 之前由这里代 ping。 */
  public void startStartupPings() {
    startupPinger.scheduleAtFixedRate(() -> {
      if (ticking) {
        startupPinger.shutdown();
        return;
      }
      sdk.health().exceptionally(e -> warn("health", "启动阶段 health ping 失败", e));
    }, 0, 2, TimeUnit.SECONDS);
  }

  public synchronized void serverStarted() {
    started = true;
  }

  public void tick(Instant now) {
    ticking = true;
    sdk.health().exceptionally(e -> warn("health", "health ping 失败", e));
    int players = platform.onlinePlayers();
    synchronized (this) {
      if (!started) {
        return;
      }
      if (!readyConfirmed) {
        requestReady();
        return;
      }
      if (players > 0) {
        emptySince = null;
        if (settings.mode() == Mode.LOBBY && !allocated && !transitionInFlight) {
          transition("allocate", sdk.allocate(), true);
        }
        return;
      }
      if (emptySince == null) {
        emptySince = now;
      }
      if (Duration.between(emptySince, now).compareTo(settings.idle()) < 0) {
        return;
      }
      switch (settings.mode()) {
        case LOBBY -> {
          if (allocated && !transitionInFlight) {
            transition("ready", sdk.ready(), false);
          }
        }
        case ROOM -> requestShutdown(now);
      }
    }
  }

  public void playerJoined(UUID player) {
    sdk.listAdd(PLAYERS_LIST, player.toString())
        .exceptionally(e -> warn("list", "players 列表加入失败", e));
  }

  public void playerLeft(UUID player) {
    sdk.listRemove(PLAYERS_LIST, player.toString())
        .exceptionally(e -> warn("list", "players 列表移除失败", e));
  }

  @Override
  public void close() {
    startupPinger.shutdownNow();
  }

  private void requestReady() {
    if (readyInFlight) {
      return;
    }
    readyInFlight = true;
    sdk.ready().whenComplete((ok, e) -> {
      synchronized (this) {
        readyInFlight = false;
        if (e == null) {
          readyConfirmed = true;
          log.info("Agones: Ready（模式 " + settings.mode() + "，空闲阈值 " + settings.idle().toSeconds() + " 秒）");
        } else {
          warn("ready", "Ready 失败，下次 tick 重试", e);
        }
      }
    });
  }

  /** LOBBY 模式在 Allocated 和 Ready 之间切换，成功后才更新本地状态。 */
  private void transition(String what, java.util.concurrent.CompletableFuture<Void> call, boolean toAllocated) {
    transitionInFlight = true;
    call.whenComplete((ok, e) -> {
      synchronized (this) {
        transitionInFlight = false;
        if (e == null) {
          allocated = toAllocated;
          log.info("Agones: " + what + " 成功，现在是 " + (toAllocated ? "Allocated" : "Ready"));
        } else {
          warn(what, what + " 失败，下次 tick 重试", e);
        }
      }
    });
  }

  private void requestShutdown(Instant now) {
    if (shutdownRequestedAt != null && Duration.between(shutdownRequestedAt, now).compareTo(RETRY_SHUTDOWN) < 0) {
      return;
    }
    if (shutdownRequestedAt == null) {
      log.info("Agones: 空闲 " + settings.idle().toSeconds() + " 秒，存盘后 Shutdown");
      // 必须在 Shutdown 之前：之后 Pod 随时会被删。
      platform.saveAll();
    }
    shutdownRequestedAt = now;
    sdk.shutdown().exceptionally(e -> warn("shutdown", "Shutdown 失败，稍后重试", e));
  }

  /** 同一类错误一分钟最多记一次，sidecar 挂掉时不刷屏。 */
  private synchronized Void warn(String key, String message, Throwable e) {
    Instant now = Instant.now();
    Instant last = lastLogged.get(key);
    if (last == null || Duration.between(last, now).toSeconds() >= 60) {
      lastLogged.put(key, now);
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      log.log(Level.WARNING, "Agones: " + message + ": " + cause);
    }
    return null;
  }
}
