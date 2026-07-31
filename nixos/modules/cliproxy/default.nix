{
  config,
  lib,
  pkgs,
  inputs,
  ...
}: let
  cfg = config.services.cliproxy;
  configPath = config.sops.templates."cli-proxy-api.yaml".path;
in {
  options.services.cliproxy = {
    enable = lib.mkEnableOption "CLIProxyAPI:把 Codex/Claude 等订阅制 CLI 的 OAuth 凭据包装成 OpenAI 兼容 API";

    package = lib.mkOption {
      type = lib.types.package;
      default = inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.cli-proxy-api;
      defaultText = lib.literalExpression "inputs.llm-agents.packages.\${system}.cli-proxy-api";
      description = ''
        来自 numtide/llm-agents.nix。nixpkgs 里没有这个包,而上游发版极快
        (2026-07 一个月 64 个 release),自己维护 vendorHash 跟不动。

        那个 flake 故意没有 follows 我们的 nixpkgs:follow 之后 Go 工具链和全部
        依赖都会换掉,derivation hash 跟着变,他们预构建的产物一个都命不中。
        对应的 substituter(cache.numtide.com)写在 modules/nix-settings.nix。
      '';
    };

    bindAddress = lib.mkOption {
      type = lib.types.str;
      example = "100.64.0.3";
      description = ''
        **必须是 tailscale 地址,不要填 0.0.0.0。**

        这个端点背后是一个真人的 ChatGPT 订阅凭据,谁能连上谁就能拿这个账号
        跑量,而拿订阅当 API 用本身已经违反 OpenAI ToS,被人刷到量就是封号。
        只绑 tailscale 地址意味着公网 IP 上压根没有这个监听,比"开在公网再靠
        一个 token 拦"强一个数量级。
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8317;
      description = "上游默认端口。";
    };
  };

  config = lib.mkIf cfg.enable {
    # 客户端调用本代理时要出示的 key。键名固定,`just check-sops` 会检查它
    # 在 secrets/hosts/<host>.yaml 里真的存在。
    sops.secrets."cliproxy/api_key" = {};

    users.users.cliproxy = {
      isSystemUser = true;
      group = "cliproxy";
    };
    users.groups.cliproxy = {};

    # 整份 config.yaml 由 sops 渲染:里面唯一的秘密是 api-keys,而 store 是
    # world-readable。owner 给服务用户,因为进程要读它。
    sops.templates."cli-proxy-api.yaml" = {
      owner = "cliproxy";
      restartUnits = ["cliproxy.service"];
      content = ''
        # 由 nixos/modules/cliproxy 生成,不要手改 —— 每次 rebuild 都会覆盖。
        host: "${cfg.bindAddress}"
        port: ${toString cfg.port}

        # OAuth token 是运行时刷新并回写的(Codex 提前 5 天续期),所以这里必须
        # 是可写且跨重启保留的目录,不能是 store 路径,也不能用 sops 管。
        auth-dir: "/var/lib/cli-proxy-api/auths"

        api-keys:
          - "${config.sops.placeholder."cliproxy/api_key"}"

        remote-management:
          # secret-key 留空 = /v0/management/* 整个 404。
          #
          # 这不只是"少开一个接口":secret-key 一旦填了明文,程序会在每次启动时
          # 把它 bcrypt 之后**回写 config.yaml**,而管理接口的每个写操作也会回写。
          # 我们这份 config 是 sops 渲染的只读文件,回写要么失败要么被下次 rebuild
          # 冲掉。留空之后它一次都不会写。
          secret-key: ""
          allow-remote: false
          # 管理面板是运行时从 GitHub Releases 下载到 static/ 的,还会定期自更新。
          # 我们不用面板,关掉省一条外连和一个可写目录。
          disable-control-panel: true

        debug: false
      '';
    };

    # 这套原先是跑在 docker 里的,容器以 root 跑,所以 auths/ 下已有的凭据是
    # root 属主。换成原生服务之后进程是 cliproxy 用户,读不到也写不回去 ——
    # token 到期续不上就直接失效。Z 是递归改属主/权限且幂等,所以这条长期留着
    # 也无害。
    systemd.tmpfiles.rules = [
      "Z /var/lib/cli-proxy-api 0700 cliproxy cliproxy -"
    ];

    systemd.services.cliproxy = {
      description = "CLIProxyAPI";
      wantedBy = ["multi-user.target"];
      # 绑的是 tailscale 地址,tailscaled 没起来的话这个地址还不存在,bind 会失败。
      after = ["network-online.target" "tailscaled.service"];
      wants = ["network-online.target" "tailscaled.service"];

      serviceConfig = {
        User = "cliproxy";
        Group = "cliproxy";
        StateDirectory = "cli-proxy-api";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/cli-proxy-api";
        # -config 显式给路径。不给的话它按 $PWD/config.yaml 找,依赖 cwd 太隐晦。
        ExecStart = "${lib.getExe cfg.package} -config ${configPath}";
        Restart = "always";
        RestartSec = "10s";

        # 它只需要读 config、读写 auth-dir、对外发 HTTPS。
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
        RestrictNamespaces = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
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
        provider="''${1:-codex}"
        case "$provider" in
          codex)  flag=-codex-device-login ;;
          claude) flag=-claude-login ;;
          *) echo "用法: cliproxy-login [codex|claude]" >&2; exit 1 ;;
        esac
        # 必须以服务用户身份跑:凭据文件的属主要和服务一致,否则它后台续期时
        # 写不回去,token 过期就直接失效了。
        if [ "$(id -un)" != "cliproxy" ]; then
          exec sudo -u cliproxy -- "$0" "$@"
        fi
        cd /var/lib/cliproxy
        echo "== 跑 $flag,凭据写进 /var/lib/cli-proxy-api/auths =="
        echo "== 登完执行: sudo systemctl restart cliproxy =="
        exec ${lib.getExe cfg.package} -config ${configPath} "$flag"
      '')
    ];
  };
}
