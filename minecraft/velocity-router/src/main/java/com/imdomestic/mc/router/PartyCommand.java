package com.imdomestic.mc.router;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

/** /party（别名 /p）：组队。队伍状态在 {@link Parties}，跟着队长进房间在 {@link Rooms}。 */
final class PartyCommand implements SimpleCommand {
  private static final List<String> SUBCOMMANDS =
      List.of("invite", "accept", "leave", "list", "warp", "kick", "transfer", "disband");

  private final ProxyServer proxy;
  private final Parties parties;
  private final Rooms rooms;

  PartyCommand(ProxyServer proxy, Parties parties, Rooms rooms) {
    this.proxy = proxy;
    this.parties = parties;
    this.rooms = rooms;
  }

  @Override
  public void execute(Invocation invocation) {
    if (!(invocation.source() instanceof Player player)) {
      invocation.source().sendMessage(Component.text("只有玩家能用这个命令", NamedTextColor.RED));
      return;
    }
    String[] args = invocation.arguments();
    String sub = args.length == 0 ? "list" : args[0].toLowerCase(Locale.ROOT);
    String arg = args.length > 1 ? args[1] : null;
    switch (sub) {
      case "invite" -> {
        if (arg == null) {
          usage(player, "/party invite <玩家>");
        } else {
          parties.invite(player, arg);
        }
      }
      case "accept" -> parties.accept(player, arg).ifPresent(leader -> rooms.joinLeader(player, leader));
      case "leave" -> parties.leave(player);
      case "list", "info" -> parties.info(player);
      case "warp" -> rooms.warpParty(player);
      case "kick" -> {
        if (arg == null) {
          usage(player, "/party kick <玩家>");
        } else {
          parties.kick(player, arg);
        }
      }
      case "transfer" -> {
        if (arg == null) {
          usage(player, "/party transfer <玩家>");
        } else {
          parties.transfer(player, arg);
        }
      }
      case "disband" -> parties.disband(player);
      case "help" -> help(player);
      default -> {
        // /party <玩家> 是 /party invite <玩家> 的简写。
        if (args.length == 1 && proxy.getPlayer(args[0]).isPresent()) {
          parties.invite(player, args[0]);
        } else {
          help(player);
        }
      }
    }
  }

  @Override
  public List<String> suggest(Invocation invocation) {
    if (!(invocation.source() instanceof Player player)) {
      return List.of();
    }
    String[] args = invocation.arguments();
    if (args.length <= 1) {
      return filter(SUBCOMMANDS, args.length == 0 ? "" : args[0]);
    }
    String last = args[args.length - 1];
    if (args.length != 2) {
      return List.of();
    }
    return switch (args[0].toLowerCase(Locale.ROOT)) {
      case "invite" -> filter(proxy.getAllPlayers().stream()
          .filter(p -> !p.equals(player))
          .map(Player::getUsername)
          .toList(), last);
      case "accept" -> filter(parties.inviterNames(player), last);
      case "kick", "transfer" -> filter(parties.memberNames(player), last);
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

  private static void help(Player player) {
    player.sendMessage(Component.text(String.join("\n",
        "组队命令（/party 可以简写成 /p）：",
        "  /party invite <玩家>     邀请别人进队伍，也可以直接 /p <玩家>",
        "  /party accept [玩家]     接受邀请",
        "  /party list              队伍成员和他们在哪",
        "  /party leave             离开队伍",
        "  /party warp              队长：把队员都拉到自己这里",
        "  /party kick <玩家>       队长：移出队伍",
        "  /party transfer <玩家>   队长：把队长交给别人",
        "  /party disband           队长：解散队伍",
        "队长用 /play、/room create、/room join 进房间时，队员会自动跟进去。"),
        NamedTextColor.AQUA));
  }
}
