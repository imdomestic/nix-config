{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.cliproxy;
in {
  options.services.cliproxy = {
    enable = lib.mkEnableOption "CLIProxyAPI:把 Codex/Claude 等订阅制 CLI 的 OAuth 凭据包装成 OpenAI 兼容 API";

    image = lib.mkOption {
      type = lib.types.str;
      default = "eceasy/cli-proxy-api:v7.2.111";
      description = ''
        必须钉死版本。上游 2026 年 7 月一个月发了 64 个 release(v7.2.104 到
        v7.2.111 全在 7 月 28-30 三天里),`latest` 等于每次重启都换一个不知道
        改了什么的二进制。nixpkgs 里没有这个包,所以走官方镜像。
      '';
    };

    bindAddress = lib.mkOption {
      type = lib.types.str;
      example = "100.64.0.3";
      description = ''
        程序自己绑的地址。**必须是 tailscale 地址,不要填 0.0.0.0。**

        这个端点背后是一个真人的 ChatGPT 订阅凭据,谁能连上谁就能拿你的账号
        跑量,而拿订阅当 API 用本身已经是违反 OpenAI ToS 的,被人刷到量就是
        封号。只绑 tailscale 地址意味着公网 IP 上压根没有这个监听,比"开在
        公网再靠一个 token 拦"强一个数量级。

        注意容器跑的是 host 网络(见下面 extraOptions 的说明),所以这里填什么
        就真的绑什么,没有 docker 的端口映射兜底。
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8317;
      description = "上游默认端口。";
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/cli-proxy-api";
      description = ''
        OAuth 凭据落盘的地方。**不能放 nix store,也不能用 sops 管。**
        token 是运行时刷新并回写的(Codex 提前 5 天续期),所以这个目录必须
        可写且跨重启保留。
      '';
    };

  };

  config = lib.mkIf cfg.enable {
    virtualisation.oci-containers.backend = lib.mkDefault "docker";

    # 客户端调用本代理时要出示的 key。键名固定,`just check-sops` 会检查它
    # 在 secrets/hosts/<host>.yaml 里真的存在。
    sops.secrets."cliproxy/api_key" = {};

    # 整份 config.yaml 由 sops 渲染:里面唯一的秘密是 api-keys,而 store 是
    # world-readable。渲染结果在 /run/secrets/rendered 下,root-only,容器以
    # root 跑,读得到。
    sops.templates."cli-proxy-api.yaml" = {
      restartUnits = ["docker-cli-proxy-api.service"];
      content = ''
        # 由 nixos/modules/cliproxy 生成,不要手改 —— 每次 rebuild 都会覆盖。
        host: "${cfg.bindAddress}"
        port: ${toString cfg.port}

        auth-dir: "/auths"

        api-keys:
          - "${config.sops.placeholder."cliproxy/api_key"}"

        remote-management:
          # secret-key 留空 = /v0/management/* 整个 404。
          #
          # 这不只是"少开一个接口":secret-key 一旦填了明文,程序会在每次启动时
          # 把它 bcrypt 之后**回写 config.yaml**,而管理接口的每个写操作也会回写。
          # 我们这份 config 是 sops 渲染的只读文件,回写要么失败要么被下次 rebuild
          # 冲掉。留空之后它一次都不会写,只读挂载才是安全的。
          secret-key: ""
          allow-remote: false
          # 管理面板是运行时从 GitHub Releases 下载到 static/ 的,还会定期自更新。
          # 我们不用面板,关掉省一条外连和一个可写目录。
          disable-control-panel: true

        debug: false
      '';
    };

    virtualisation.oci-containers.containers.cli-proxy-api = {
      image = cfg.image;

      # host 网络是必须的,不是图省事。
      #
      # 实测:默认 bridge 网络下容器访问 auth.openai.com 得到 403,host 网络下
      # 得到 200 —— 同样的 UA,差别只在出口 IP。dae 是透明代理,只接管本机流量;
      # 容器走 bridge 时是被"转发"出去的,dae 不管,于是用国内 IP 直连 OpenAI,
      # 被挡。host 网络下容器和宿主同一个 netns,dae 正常接管,经 r5sjp 从日本出去。
      #
      # 代价是没有 docker 的端口映射,绑哪个地址完全由上面 config.yaml 的 host
      # 决定 —— 所以 bindAddress 写错就是直接暴露在公网上。
      extraOptions = ["--network=host"];

      volumes = [
        "${config.sops.templates."cli-proxy-api.yaml".path}:/CLIProxyAPI/config.yaml:ro"
        "${cfg.stateDir}/auths:/auths"
      ];
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 root root -"
      "d ${cfg.stateDir}/auths 0700 root root -"
    ];

    systemd.services.docker-cli-proxy-api = {
      # 绑的是 tailscale 地址,tailscaled 没起来的话这个地址还不存在,bind 会失败。
      after = ["tailscaled.service"];
      wants = ["tailscaled.service"];
      serviceConfig = {
        Restart = lib.mkOverride 90 "always";
        RestartSec = "10s";
      };
    };

    # 登录辅助。设备码流程不需要回调端口、不需要浏览器、不需要 SSH 隧道 ——
    # 它打印一个 URL 和一段码,你在任意一台有浏览器的机器上开那个 URL 输码即可。
    # 上游文档主推的是 `-no-browser` + `ssh -L 1455:...` 那套,那套在这里更麻烦:
    # 它会去 api.ipify.org 猜公网 IP 来拼 ssh 命令,而这台机器经 dae 出去,
    # 猜出来的是日本出口的地址,拼出来的 ssh 命令是错的。
    environment.systemPackages = [
      (pkgs.writeShellScriptBin "cliproxy-login" ''
        set -euo pipefail
        if [ "$(id -u)" -ne 0 ]; then
          echo "要 root:凭据写在 ${cfg.stateDir}/auths(0700)" >&2
          exec sudo -E "$0" "$@"
        fi
        provider="''${1:-codex}"
        case "$provider" in
          codex)  flag=-codex-device-login ;;
          claude) flag=-claude-login ;;
          *) echo "用法: cliproxy-login [codex|claude]" >&2; exit 1 ;;
        esac
        echo "== 用 ${cfg.image} 跑 $flag =="
        echo "== 凭据会写进 ${cfg.stateDir}/auths,登完 systemctl restart docker-cli-proxy-api =="
        exec ${config.virtualisation.oci-containers.backend} run --rm -it \
          --network=host \
          -v "${config.sops.templates."cli-proxy-api.yaml".path}:/CLIProxyAPI/config.yaml:ro" \
          -v "${cfg.stateDir}/auths:/auths" \
          ${cfg.image} ./CLIProxyAPI "$flag"
      '')
    ];
  };
}
