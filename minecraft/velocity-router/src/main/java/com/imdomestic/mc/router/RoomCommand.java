package com.imdomestic.mc.router;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

/** /room：开房间、进房间、列房间、邀请、关房。逻辑在 {@link Rooms}。 */
final class RoomCommand implements SimpleCommand {
  private static final List<String> SUBCOMMANDS = List.of("create", "join", "list", "invite", "info", "close");

  private final ProxyServer proxy;
  private final Rooms rooms;

  RoomCommand(ProxyServer proxy, Rooms rooms) {
    this.proxy = proxy;
    this.rooms = rooms;
  }

  @Override
  public void execute(Invocation invocation) {
    String[] args = invocation.arguments();
    String sub = args.length == 0 ? "" : args[0].toLowerCase(Locale.ROOT);
    if (sub.equals("list")) {
      rooms.list(invocation.source(), args.length > 1 ? args[1] : null);
      return;
    }
    if (!(invocation.source() instanceof Player player)) {
      invocation.source().sendMessage(Component.text("只有玩家能用这个命令", NamedTextColor.RED));
      return;
    }
    switch (sub) {
      case "create" -> {
        if (args.length < 2 || args.length > 3) {
          usage(player, "/room create <" + String.join("|", rooms.kinds()) + "> [public|private]");
        } else {
          rooms.create(player, args[1], args.length < 3 || !args[2].equalsIgnoreCase("private"));
        }
      }
      case "join" -> {
        if (args.length != 2) {
          usage(player, "/room join <房间码>");
        } else {
          rooms.join(player, args[1]);
        }
      }
      case "invite" -> {
        if (args.length != 2) {
          usage(player, "/room invite <玩家>");
        } else {
          rooms.invite(player, args[1]);
        }
      }
      case "info" -> rooms.info(player);
      case "close" -> rooms.close(player);
      default -> help(player);
    }
  }

  @Override
  public List<String> suggest(Invocation invocation) {
    String[] args = invocation.arguments();
    if (args.length <= 1) {
      return filter(SUBCOMMANDS, args.length == 0 ? "" : args[0]);
    }
    String last = args[args.length - 1];
    return switch (args[0].toLowerCase(Locale.ROOT)) {
      case "create" -> args.length == 2 ? filter(rooms.kinds(), last) : filter(List.of("public", "private"), last);
      case "list" -> args.length == 2 ? filter(rooms.kinds(), last) : List.of();
      case "join" -> args.length == 2 ? filter(rooms.codes(), last) : List.of();
      case "invite" -> args.length == 2
          ? filter(proxy.getAllPlayers().stream().map(Player::getUsername).toList(), last)
          : List.of();
      default -> List.of();
    };
  }

  private static List<String> filter(Collection<String> options, String prefix) {
    String p = prefix.toLowerCase(Locale.ROOT);
    return options.stream().filter(o -> o.toLowerCase(Locale.ROOT).startsWith(p)).toList();
  }

  private static void usage(Player player, String usage) {
    player.sendMessage(Component.text("用法：" + usage, NamedTextColor.YELLOW));
  }

  private void help(Player player) {
    player.sendMessage(Component.text(String.join("\n",
        "房间命令：",
        "  /play <类型>                    快速加入有空位的公开房间，没有就开一个",
        "  /room create <类型> [private]   自己开房间（默认公开）",
        "  /room join <房间码>             进指定房间",
        "  /room list [类型]               列出公开房间",
        "  /room invite <玩家>             邀请别人进你所在的房间",
        "  /room info                      当前房间的信息",
        "  /room close                     房主关闭房间",
        "  /lobby                          回大厅",
        "可选类型：" + String.join("、", rooms.kinds())), NamedTextColor.AQUA));
  }
}
