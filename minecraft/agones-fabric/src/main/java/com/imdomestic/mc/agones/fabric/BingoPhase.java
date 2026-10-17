package com.imdomestic.mc.agones.fabric;

import java.lang.reflect.Method;
import java.util.Locale;
import java.util.Optional;
import java.util.logging.Logger;
import net.fabricmc.loader.api.FabricLoader;

/**
 * 读 Yet Another Minecraft BINGO 的对局阶段（{@code BingoApi.getGame().getStatus()}）。
 *
 * <p>bingo 的 API jar 只打包在 mod 里，没发到 Maven 仓库，所以用反射；没装 bingo 时
 * {@link #detect} 返回空。
 */
final class BingoPhase {
  private static final String MOD_ID = "yet-another-minecraft-bingo";

  private final Method getGame;
  private final Logger log;
  private Method getStatus;
  private boolean warned;

  private BingoPhase(Method getGame, Logger log) {
    this.getGame = getGame;
    this.log = log;
  }

  static Optional<BingoPhase> detect(Logger log) {
    if (!FabricLoader.getInstance().isModLoaded(MOD_ID)) {
      return Optional.empty();
    }
    try {
      Method getGame = Class.forName("me.jfenn.bingo.api.BingoApi").getMethod("getGame");
      log.info("检测到 bingo，对局阶段会写到 GameServer 标签上");
      return Optional.of(new BingoPhase(getGame, log));
    } catch (ReflectiveOperationException e) {
      log.warning("装了 bingo 但找不到 BingoApi.getGame，不上报对局阶段：" + e);
      return Optional.empty();
    }
  }

  /** 读不到（bingo 还没初始化完，或者 API 变了）时返回 null。 */
  String current() {
    try {
      Object game = getGame.invoke(null);
      if (game == null) {
        return null;
      }
      if (getStatus == null) {
        getStatus = game.getClass().getMethod("getStatus");
      }
      Object status = getStatus.invoke(game);
      return status instanceof Enum<?> e ? phaseOf(e.name()) : null;
    } catch (ReflectiveOperationException | RuntimeException e) {
      if (!warned) {
        warned = true;
        log.info("暂时读不到 bingo 的对局阶段，读到之前不改标签：" + e);
      }
      return null;
    }
  }

  private static String phaseOf(String status) {
    return switch (status) {
      case "PREGAME" -> "waiting";
      case "STARTING" -> "starting";
      case "PLAYING" -> "playing";
      case "POSTGAME" -> "ended";
      default -> status.toLowerCase(Locale.ROOT);
    };
  }
}
