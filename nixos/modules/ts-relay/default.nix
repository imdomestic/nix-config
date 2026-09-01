# `ts-relay` —— 把某个 tailscale 对端从「打洞直连」按回「DERP 中转」。
#
# 存在的理由:直连不一定更快。悉尼→r5sjp 这条上,直连要绕 GTT 洛杉矶(276ms、
# 76 Mbps),而东京 DERP 是 111ms、22 Mbps。带宽和延迟是反的,没有哪个全面更优,
# 所以只能按当下在干什么手动选。实测对照表见
# docs/incidents.md#syd-jp-relay-beats-direct。
#
# 手段:tailscale 没有「只走中转」的开关,但直连是 UDP 打洞打出来的 —— 把去往
# 对端那个 endpoint 的 UDP 丢掉,它十秒左右就自己退回 DERP。
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.tsRelay;

  table = "ts-relay";

  ts-relay = pkgs.writeShellApplication {
    name = "ts-relay";
    # systemd 给的 PATH 里没有这些,交互式 root shell 的 PATH 也未必有 —— 一律
    # 显式列上(captive-portal 那次就是漏了 gawk 才在运行时才炸)。
    runtimeInputs = with pkgs; [tailscale nftables jq coreutils gnugrep];
    text = ''
      usage() {
        cat >&2 <<'EOF'
      用法: ts-relay <on|off|status> [对端主机名]

        on  <peer>   丢掉去往该对端当前直连 endpoint 的 UDP,逼它退回 DERP 中转
        off          删掉规则,让它重新打洞
        status       打印当前规则,以及每个对端实际走的路径

      需要 root。
      EOF
        exit 2
      }

      need_root() {
        if [ "$(id -u)" != "0" ]; then
          echo "ts-relay: 需要 root(用 sudo)" >&2
          exit 1
        fi
      }

      # 对端当前的直连 endpoint。已经在走中转时 CurAddr 是空的 —— 那种情况下
      # 没什么可拦的,直接告诉用户。
      cur_addr() {
        tailscale status --json \
          | jq -r --arg h "$1" '.Peer[] | select(.HostName == $h) | .CurAddr // ""'
      }

      case "''${1:-}" in
        on)
          need_root
          peer="''${2:-}"
          [ -n "$peer" ] || usage

          addr=$(cur_addr "$peer")
          if [ -z "$addr" ]; then
            echo "ts-relay: $peer 现在就没有直连(已在走中转),无事可做" >&2
            exit 0
          fi
          ip=''${addr%:*}
          port=''${addr##*:}

          # 单独一张表,撤销就是一句 delete table,不会碰到别人的规则。
          nft delete table inet ${table} 2>/dev/null || true
          nft add table inet ${table}
          nft "add chain inet ${table} o { type filter hook output priority 0; policy accept; }"
          nft "add chain inet ${table} i { type filter hook input priority 0; policy accept; }"
          nft add rule inet ${table} o ip daddr "$ip" udp dport "$port" drop
          nft add rule inet ${table} i ip saddr "$ip" udp sport "$port" drop

          echo "ts-relay: 已拦掉 $peer 的直连 endpoint $addr"
          echo "          约 10 秒后 tailscale 会退回 DERP;用 ts-relay status 确认。"
          ;;

        off)
          need_root
          if nft list table inet ${table} >/dev/null 2>&1; then
            nft delete table inet ${table}
            echo "ts-relay: 规则已删除,对端会重新打洞"
          else
            echo "ts-relay: 本来就没有规则"
          fi
          ;;

        status)
          if nft list table inet ${table} 2>/dev/null | grep -q drop; then
            echo "== 生效中的拦截规则 =="
            nft list table inet ${table} | grep drop
          else
            echo "== 无拦截规则(全部允许打洞) =="
          fi
          echo
          echo "== 各对端实际路径 =="
          tailscale status --json | jq -r '
            .Peer[]
            | select(.Online == true)
            | "\(.HostName)\t\(if .CurAddr != "" and .CurAddr != null
                               then "direct " + .CurAddr
                               else "relay \"" + .Relay + "\"" end)"'
          ;;

        *) usage ;;
      esac
    '';
  };
in {
  options.my.tsRelay.enable =
    lib.mkEnableOption "ts-relay —— 手动把 tailscale 对端按回 DERP 中转";

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ts-relay];
  };
}
