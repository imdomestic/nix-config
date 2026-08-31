# Captive portal 自动登录 —— 让一台没有人值守的路由器待在酒店/公寓那种
# 「先认证才给网」的网络后面。
#
# 目前只对上 MikroTik hotspot 这一种(rpi4 所在的悉尼公寓,Vostro/Superloop
# 的 iglu 网络)。表单格式是从 portal 前端的 source map 里挖出来的,连同
# 为什么用 `--resolve` 绕开 DNS,都记在 docs/incidents.md#rpi4-sydney-captive-portal。
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.captivePortal;

  login = pkgs.writeShellApplication {
    name = "captive-portal-login";
    runtimeInputs = with pkgs; [curl jq iproute2];
    text = ''
      host=${lib.escapeShellArg cfg.host}
      iface=${lib.escapeShellArg cfg.interface}

      : "''${CAPTIVE_PORTAL_USERNAMES:?credentialsFile 未提供 CAPTIVE_PORTAL_USERNAMES}"
      : "''${CAPTIVE_PORTAL_PASSWORD:?credentialsFile 未提供 CAPTIVE_PORTAL_PASSWORD}"

      # portal 的 A 记录就指向默认网关本身(hotspot 网关自己终结 TLS),所以
      # 网关地址即 portal 地址。拿它是为了喂给 curl --resolve —— **登录这一步
      # 不能依赖 DNS**:认证之前 walled garden 只放行到网关,dae 配的那些
      # 上游(alidns/dns.google)一个都解析不出来,而 --resolve 只覆盖地址、
      # 保留 SNI 和证书校验,不用降级成 --insecure。
      gw=$(ip -4 route show default dev "$iface" | awk '{print $3; exit}')
      if [ -z "$gw" ]; then
        echo "no default route on $iface yet; skipping" >&2
        exit 0
      fi

      portal() {
        curl --silent --show-error --max-time 10 \
          --resolve "$host:443:$gw" "$@"
      }

      logged_in() {
        portal "https://$host/check-login.html" 2>/dev/null \
          | jq -e '.loggedIn == "yes"' >/dev/null 2>&1
      }

      if logged_in; then
        exit 0
      fi

      # 候选用户名依次试。账号的真实 userName 是一串数字,而 portal 的登录框
      # 同时收邮箱 —— 但网关那一段是把表单原样丢给 RADIUS 的,谁能过只有试了
      # 才知道,所以两个都留着。
      for user in $CAPTIVE_PORTAL_USERNAMES; do
        # radius11=hotspot 是 portal 前端那个隐藏 form 里写死的字段,照抄。
        portal --request POST "https://$host/login" \
          --data "radius11=hotspot" \
          --data-urlencode "username=$user" \
          --data-urlencode "password=$CAPTIVE_PORTAL_PASSWORD" \
          --output /dev/null || true

        sleep 2
        if logged_in; then
          echo "captive portal: logged in as $user"
          exit 0
        fi
      done

      echo "captive portal: login failed for all candidate usernames" >&2
      exit 1
    '';
  };
in {
  options.my.captivePortal = {
    enable = lib.mkEnableOption "captive portal 自动登录";

    interface = lib.mkOption {
      type = lib.types.str;
      example = "enp1s0u2";
      description = "走 captive portal 的 WAN 接口,用来取默认网关。";
    };

    host = lib.mkOption {
      type = lib.types.str;
      example = "iglu.authentication.technology";
      description = ''
        hotspot 网关的主机名。它的 A 记录指向网关的内网地址,证书也签在
        这个名字上,所以脚本用 `--resolve` 把它钉到默认网关。
      '';
    };

    credentialsFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        systemd EnvironmentFile,提供 `CAPTIVE_PORTAL_USERNAMES`
        (空格分隔的候选用户名) 和 `CAPTIVE_PORTAL_PASSWORD`。
        走 sops,不要进 nix store。
      '';
    };

    interval = lib.mkOption {
      type = lib.types.str;
      default = "2min";
      description = ''
        复查间隔。已登录时一次检查只是一个到网关的 HTTPS 请求,几乎没有开销;
        而 DHCP 租约只有 1 小时、hotspot 还有自己的会话超时,掉线后越快补上
        越好 —— 这台后面挂着整个 LAN。
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.captive-portal-login = {
      description = "Log in to the captive portal on ${cfg.interface}";
      after = ["network-online.target"];
      wants = ["network-online.target"];

      serviceConfig = {
        Type = "oneshot";
        EnvironmentFile = cfg.credentialsFile;
        ExecStart = lib.getExe login;

        # 只读根 + 无新特权:这个单元要做的全部事情就是发两个 HTTP 请求。
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
    };

    # 由 timer 驱动,而不是 wantedBy = multi-user.target。开机时网卡可能还没
    # 拿到租约,那种情况下脚本直接退出(exit 0),等下一次 tick 就行 —— 不需要
    # 一个开机即 failed 的单元。
    systemd.timers.captive-portal-login = {
      wantedBy = ["timers.target"];
      timerConfig = {
        OnBootSec = "20s";
        OnUnitActiveSec = cfg.interval;
        AccuracySec = "5s";
      };
    };
  };
}
