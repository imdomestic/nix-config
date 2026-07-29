# 给朋友用的小型代理订阅服务。
#
# 用量和到期不靠面板,靠 Xray 自己的 StatsService/HandlerService:
# 每个用户在 friends-in 入口下有独立 email,statsquery 取增量,超限就
# 用 rmu 踢掉 —— 热生效,不用重启 Xray,也就不会打断其它入口(包括
# r5sjp 那条反向隧道)。
#
# 用户的 UUID 和订阅 token 由控制器在运行时签发并只存在 stateDir 里,
# 所以加一个朋友只要在这里加几行声明,既不用动 sops 也不会进 git。
{
  config,
  lib,
  pkgs,
  ...
}:
with lib; let
  cfg = config.services.airport;

  # 两个脚本和 CLI 共用这一份;放进 store 是安全的,里面只有配额和到期,
  # 凭据都在 stateDir。
  configFile = pkgs.writeText "airport.json" (builtins.toJSON {
    inherit (cfg) inboundTag apiAddress timezone stateDir;
    xrayBin = "${config.services.xray.package}/bin/xray";
    server = {
      inherit (cfg.server) address port sni fingerprint flow name;
      publicKeyFile = cfg.server.publicKeyFile;
      shortIdFile = cfg.server.shortIdFile;
    };
    subscription = {inherit (cfg.subscription) listen baseUrl;};
    users = mapAttrs (_: u: {inherit (u) quotaGB expires enabled;}) cfg.users;
  });

  python = "${pkgs.python3}/bin/python3";

  airportCli = pkgs.writeShellScriptBin "airport" ''
    export AIRPORT_CONFIG=${configFile}
    exec ${python} ${./cli.py} "$@"
  '';
in {
  options.services.airport = {
    enable = mkEnableOption "给朋友用的代理订阅服务";

    inboundTag = mkOption {
      type = types.str;
      default = "friends-in";
      description = "被托管的 Xray 入口 tag。控制器只增删这一个入口下的用户。";
    };

    apiAddress = mkOption {
      type = types.str;
      default = "127.0.0.1:10085";
      description = "Xray 的 api.listen 地址。";
    };

    timezone = mkOption {
      type = types.str;
      default = "Asia/Shanghai";
      description = "判断到期日用的时区。";
    };

    interval = mkOption {
      type = types.str;
      default = "2min";
      description = "两次调和之间的间隔;决定超额后最长多久被踢。";
    };

    stateDir = mkOption {
      type = types.path;
      default = "/var/lib/airport";
      description = "账本位置。里面有每个用户的 UUID、订阅 token 和累计用量。";
    };

    server = {
      address = mkOption {
        type = types.str;
        description = "订阅里写给客户端的服务端地址。";
      };
      port = mkOption {
        type = types.port;
        description = "friends-in 入口的端口。";
      };
      name = mkOption {
        type = types.str;
        default = "airport";
        description = "客户端里显示的节点名。";
      };
      sni = mkOption {
        type = types.str;
        default = "www.apple.com";
      };
      fingerprint = mkOption {
        type = types.str;
        default = "chrome";
      };
      flow = mkOption {
        type = types.str;
        default = "xtls-rprx-vision";
      };
      publicKeyFile = mkOption {
        type = types.path;
        description = "Reality 公钥文件,需要 airport 用户可读。";
      };
      shortIdFile = mkOption {
        type = types.path;
        description = "friends-in 的 shortId 文件,需要 airport 用户可读。";
      };
    };

    subscription = {
      listen = mkOption {
        type = types.str;
        default = "127.0.0.1:8081";
        description = "订阅服务的监听地址。只听回环,TLS 交给前面的 nginx。";
      };
      baseUrl = mkOption {
        type = types.str;
        description = "对外的订阅前缀,例如 https://host.example.com:8443。";
      };
    };

    users = mkOption {
      default = {};
      description = "朋友列表。属性名就是 Xray 里的 email,也是 CLI 里的用户名。";
      type = types.attrsOf (types.submodule {
        options = {
          quotaGB = mkOption {
            type = types.ints.unsigned;
            description = "总流量上限(GiB,上下行合计)。用完为止,不自动重置;想续期改这个数或跑 airport reset。0 表示不限。";
          };
          expires = mkOption {
            type = types.strMatching "[0-9]{4}-[0-9]{2}-[0-9]{2}";
            description = "到期日 YYYY-MM-DD,当天仍然有效。";
          };
          enabled = mkOption {
            type = types.bool;
            default = true;
            description = "置 false 可以立刻停掉某人而不用删配置。";
          };
        };
      });
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.xray.enable;
        message = "services.airport 需要 services.xray 一起启用。";
      }
    ];

    users.users.airport = {
      isSystemUser = true;
      group = "airport";
      description = "airport 订阅服务";
    };
    users.groups.airport = {};

    # 控制器和订阅服务都不需要特权:一个只跟回环上的 Xray API 说话,
    # 一个只读账本,所以两个都跑在 airport 用户下。
    systemd.services.airport-sync = {
      description = "调和 airport 用户与 Xray 的实际状态";
      after = ["xray.service"];
      # 让 xray 一起来就跑一次:Xray 重启会把 friends-in 清回空 clients,
      # 不补一次的话朋友要等到下一个 timer 周期才能连上。
      wantedBy = ["xray.service" "multi-user.target"];
      environment.AIRPORT_CONFIG = "${configFile}";
      serviceConfig = {
        Type = "oneshot";
        User = "airport";
        Group = "airport";
        StateDirectory = "airport";
        StateDirectoryMode = "0700";
        ExecStart = "${python} ${./controller.py}";
        # xray 起来到 API 真正监听之间有个窗口,撞上了就退非零,重试即可
        Restart = "on-failure";
        RestartSec = "5s";
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
      };
    };

    systemd.timers.airport-sync = {
      description = "定期调和 airport 用户";
      wantedBy = ["timers.target"];
      timerConfig = {
        OnBootSec = cfg.interval;
        OnUnitActiveSec = cfg.interval;
        AccuracySec = "10s";
      };
    };

    systemd.services.airport-sub = {
      description = "airport 订阅服务";
      after = ["network.target"];
      wantedBy = ["multi-user.target"];
      environment.AIRPORT_CONFIG = "${configFile}";
      serviceConfig = {
        Type = "simple";
        User = "airport";
        Group = "airport";
        StateDirectory = "airport";
        StateDirectoryMode = "0700";
        ExecStart = "${python} ${./subserver.py}";
        Restart = "always";
        RestartSec = "5s";
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6"];
      };
    };

    environment.systemPackages = [airportCli];
  };
}
