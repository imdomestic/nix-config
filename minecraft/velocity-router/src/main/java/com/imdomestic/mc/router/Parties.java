package com.imdomestic.mc.router;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import net.kyori.adventure.text.format.NamedTextColor;

/**
 * 组队。队长进房间时（/play、/room create、/room join 都算），队员跟着进同一个房间，这部分在
 * {@link Rooms} 里；这里只管谁和谁一队。
 *
 * <p>队伍只存在这台 Velocity 的内存里，代理重启就散了。房间状态放在 GameServer 上是因为 QQ bot
 * 和多副本 Velocity 要读；队伍只有这台代理自己用，以后多副本时再挪到共享存储。
 */
final class Parties {
  private static final Duration INVITE_TTL = Duration.ofMinutes(1);

  /** 成员按入队顺序排，第一个是队长；队长走了，下一个人接任。 */
  private static final class Party {
    final List<UUID> members = new ArrayList<>();

    UUID leader() {
      return members.get(0);
    }
  }

  private record Invite(UUID inviterId, String inviterName, Instant expires) {}

  private final ProxyServer proxy;
  private final Routes routes;
  private final Map<UUID, Party> byMember = new HashMap<>();
  /** 被邀请的人 → 邀请人名字（小写）→ 邀请，按邀请时间排。 */
  private final Map<UUID, LinkedHashMap<String, Invite>> invites = new HashMap<>();

  Parties(ProxyServer proxy, Routes routes) {
    this.proxy = proxy;
    this.routes = routes;
  }

  synchronized void invite(Player inviter, String targetName) {
    Optional<Player> found = proxy.getPlayer(targetName);
    if (found.isEmpty()) {
      inviter.sendMessage(Component.text(targetName + " 不在线", NamedTextColor.RED));
      return;
    }
    Player target = found.get();
    if (target.equals(inviter)) {
      inviter.sendMessage(Component.text("不能邀请自己", NamedTextColor.RED));
      return;
    }
    Party party = byMember.get(inviter.getUniqueId());
    if (party != null && party.members.contains(target.getUniqueId())) {
      inviter.sendMessage(Component.text(target.getUsername() + " 已经在队伍里了", NamedTextColor.YELLOW));
      return;
    }
    LinkedHashMap<String, Invite> pending = invites.computeIfAbsent(target.getUniqueId(), id -> new LinkedHashMap<>());
    String key = key(inviter.getUsername());
    pending.remove(key);
    pending.put(key, new Invite(inviter.getUniqueId(), inviter.getUsername(), Instant.now().plus(INVITE_TTL)));
    String accept = "/party accept " + inviter.getUsername();
    target.sendMessage(Component.text(inviter.getUsername() + " 邀请你加入队伍", NamedTextColor.AQUA)
        .append(Component.text(" [接受]", NamedTextColor.GREEN)
            .clickEvent(ClickEvent.runCommand(accept))
            .hoverEvent(HoverEvent.showText(Component.text(accept)))));
    inviter.sendMessage(Component.text("已邀请 " + target.getUsername() + "，" + INVITE_TTL.toMinutes()
        + " 分钟内有效", NamedTextColor.GREEN));
  }

  /**
   * 接受邀请。不写邀请人就接受最近的一个。已经在别的队伍里的话先离开那边。
   *
   * @return 成功时返回新队伍的队长，调用方据此把人带进队长所在的房间
   */
  synchronized Optional<Player> accept(Player player, String inviterName) {
    LinkedHashMap<String, Invite> pending = invites.getOrDefault(player.getUniqueId(), new LinkedHashMap<>());
    pending.values().removeIf(i -> i.expires().isBefore(Instant.now()));
    Invite invite = inviterName == null
        ? pending.values().stream().reduce((a, b) -> b).orElse(null)
        : pending.get(key(inviterName));
    if (invite == null) {
      player.sendMessage(Component.text(inviterName == null ? "没有待处理的邀请"
          : "没有 " + inviterName + " 的邀请（邀请 " + INVITE_TTL.toMinutes() + " 分钟后失效）", NamedTextColor.RED));
      return Optional.empty();
    }
    pending.remove(key(invite.inviterName()));
    if (pending.isEmpty()) {
      invites.remove(player.getUniqueId());
    }
    Optional<Player> inviter = proxy.getPlayer(invite.inviterId());
    if (inviter.isEmpty()) {
      player.sendMessage(Component.text(invite.inviterName() + " 已经下线了", NamedTextColor.RED));
      return Optional.empty();
    }
    Party party = byMember.get(invite.inviterId());
    if (party == null) {
      party = new Party();
      party.members.add(invite.inviterId());
      byMember.put(invite.inviterId(), party);
    }
    if (party.members.contains(player.getUniqueId())) {
      player.sendMessage(Component.text("你已经在这个队伍里了", NamedTextColor.YELLOW));
      return Optional.empty();
    }
    if (byMember.containsKey(player.getUniqueId())) {
      remove(player, false);
    }
    party.members.add(player.getUniqueId());
    byMember.put(player.getUniqueId(), party);
    broadcast(party, Component.text(player.getUsername() + " 加入了队伍（" + party.members.size() + " 人）",
        NamedTextColor.GREEN));
    return proxy.getPlayer(party.leader());
  }

  synchronized void leave(Player player) {
    if (!byMember.containsKey(player.getUniqueId())) {
      player.sendMessage(Component.text("你不在队伍里", NamedTextColor.YELLOW));
      return;
    }
    remove(player, false);
    player.sendMessage(Component.text("你离开了队伍", NamedTextColor.YELLOW));
  }

  /** 下线就离队，收到的邀请也作废。 */
  synchronized void disconnected(Player player) {
    invites.remove(player.getUniqueId());
    if (byMember.containsKey(player.getUniqueId())) {
      remove(player, false);
    }
  }

  synchronized void kick(Player leader, String targetName) {
    Party party = ledBy(leader);
    if (party == null) {
      return;
    }
    Optional<Player> target = member(party, targetName);
    if (target.isEmpty() || target.get().equals(leader)) {
      leader.sendMessage(Component.text(targetName + " 不在你的队伍里", NamedTextColor.RED));
      return;
    }
    remove(target.get(), true);
    target.get().sendMessage(Component.text("你被 " + leader.getUsername() + " 移出了队伍", NamedTextColor.YELLOW));
  }

  synchronized void transfer(Player leader, String targetName) {
    Party party = ledBy(leader);
    if (party == null) {
      return;
    }
    Optional<Player> target = member(party, targetName);
    if (target.isEmpty() || target.get().equals(leader)) {
      leader.sendMessage(Component.text(targetName + " 不在你的队伍里", NamedTextColor.RED));
      return;
    }
    party.members.remove(target.get().getUniqueId());
    party.members.add(0, target.get().getUniqueId());
    broadcast(party, Component.text(target.get().getUsername() + " 现在是队长", NamedTextColor.GREEN));
  }

  synchronized void disband(Player leader) {
    Party party = ledBy(leader);
    if (party == null) {
      return;
    }
    broadcast(party, Component.text(leader.getUsername() + " 解散了队伍", NamedTextColor.YELLOW));
    party.members.forEach(byMember::remove);
  }

  synchronized void info(Player player) {
    Party party = byMember.get(player.getUniqueId());
    if (party == null) {
      player.sendMessage(Component.text("你不在队伍里。用 /party invite <玩家> 组队", NamedTextColor.YELLOW));
      return;
    }
    List<String> lines = new ArrayList<>();
    for (UUID id : party.members) {
      String name = proxy.getPlayer(id).map(Player::getUsername).orElse("?");
      String where = proxy.getPlayer(id).flatMap(Player::getCurrentServer)
          .map(c -> routes.describe(c.getServer())).orElse("-");
      lines.add((id.equals(party.leader()) ? "★" : "  ") + name + "（" + where + "）");
    }
    player.sendMessage(Component.text("队伍（" + party.members.size() + " 人，★ 是队长）：\n" + String.join("\n", lines),
        NamedTextColor.AQUA));
  }

  /** 队长的其他在线队员；不是队长（或者不在队伍里）就是空的。 */
  synchronized List<Player> followers(Player leader) {
    Party party = byMember.get(leader.getUniqueId());
    if (party == null || !party.leader().equals(leader.getUniqueId())) {
      return List.of();
    }
    return party.members.stream()
        .filter(id -> !id.equals(leader.getUniqueId()))
        .map(proxy::getPlayer)
        .flatMap(Optional::stream)
        .toList();
  }

  synchronized boolean isLeader(Player player) {
    Party party = byMember.get(player.getUniqueId());
    return party != null && party.leader().equals(player.getUniqueId());
  }

  /** /party 补全用：自己队伍里的其他人。 */
  synchronized List<String> memberNames(Player player) {
    Party party = byMember.get(player.getUniqueId());
    if (party == null) {
      return List.of();
    }
    return party.members.stream()
        .filter(id -> !id.equals(player.getUniqueId()))
        .map(proxy::getPlayer)
        .flatMap(Optional::stream)
        .map(Player::getUsername)
        .toList();
  }

  synchronized List<String> inviterNames(Player player) {
    return invites.getOrDefault(player.getUniqueId(), new LinkedHashMap<>()).values().stream()
        .filter(i -> i.expires().isAfter(Instant.now()))
        .map(Invite::inviterName)
        .toList();
  }

  /** 只有队长能做的事：不是队长就提示并返回 null。 */
  private Party ledBy(Player player) {
    Party party = byMember.get(player.getUniqueId());
    if (party == null) {
      player.sendMessage(Component.text("你不在队伍里", NamedTextColor.RED));
      return null;
    }
    if (!party.leader().equals(player.getUniqueId())) {
      String leader = proxy.getPlayer(party.leader()).map(Player::getUsername).orElse("队长");
      player.sendMessage(Component.text("只有队长（" + leader + "）能这么做", NamedTextColor.RED));
      return null;
    }
    return party;
  }

  private Optional<Player> member(Party party, String name) {
    return proxy.getPlayer(name).filter(p -> party.members.contains(p.getUniqueId()));
  }

  /** 把人移出队伍。剩一个人时队伍解散；队长走了由下一个人接任。 */
  private void remove(Player player, boolean kicked) {
    Party party = byMember.remove(player.getUniqueId());
    boolean wasLeader = party.leader().equals(player.getUniqueId());
    party.members.remove(player.getUniqueId());
    String what = player.getUsername() + (kicked ? " 被移出了队伍" : " 离开了队伍");
    if (party.members.size() <= 1) {
      broadcast(party, Component.text(what + "，队伍只剩你一个人，解散了", NamedTextColor.YELLOW));
      party.members.forEach(byMember::remove);
      party.members.clear();
      return;
    }
    if (wasLeader) {
      what += "，新队长是 " + proxy.getPlayer(party.leader()).map(Player::getUsername).orElse("?");
    }
    broadcast(party, Component.text(what, NamedTextColor.YELLOW));
  }

  private void broadcast(Party party, Component message) {
    for (UUID id : party.members) {
      proxy.getPlayer(id).ifPresent(p -> p.sendMessage(message));
    }
  }

  private static String key(String name) {
    return name.toLowerCase(Locale.ROOT);
  }
}
