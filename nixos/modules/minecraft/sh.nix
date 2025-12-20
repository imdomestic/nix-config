{pkgs, ...}: let
  forwardingSecret = ["hbhbhb"];
in {
  services.minecraft-servers = {
    enable = true;
    eula = true;

    servers.proxy = {
      enable = true;
      package = pkgs.velocityServers.velocity; # 最新 velocity :contentReference[oaicite:14]{index=14}
      openFirewall = false;

      # secret 文件：用 txt 生成最省事（nix-minecraft 支持 txt 自动生成）:contentReference[oaicite:15]{index=15}
      symlinks."forwarding.secret" = pkgs.writeText "forwarding.secret" forwardingSecret;

      symlinks."plugins/ViaVerion.jar" = pkgs.fetchurl {
        url = "https://github.com/ViaVersion/ViaVersion/releases/download/5.6.0/ViaVersion-5.6.0.jar";
        sha256 = "sha256-VAlqr/sa4899o9NI1ckgpHIXWuwsnbm4lBYZDWyQnms=";
      };

      symlinks."plugins/ViaBackwards.jar" = pkgs.fetchurl {
        url = "https://github.com/ViaVersion/ViaBackwards/releases/download/5.6.0/ViaBackwards-5.6.0.jar";
        sha256 = "sha256-osVDte0mpTDCH6osoY+EEm3N/t4prsd6OuAhK3x5E6Y=";
      };

      symlinks."plugins/LuckPerms.jar" = pkgs.fetchurl {
        url = "https://download.luckperms.net/1610/velocity/LuckPerms-Velocity-5.5.21.jar";
        sha256 = "";
      };

      # velocity.toml：关键几项写上即可
      files."velocity.toml".value = {
        config-version = "2.7"; # 默认配置里有这个字段 :contentReference[oaicite:16]{index=16}
        bind = "0.0.0.0:25565";
        motd = "Velocity Proxy";
        show-max-players = 100000;
        online-mode = true;

        player-info-forwarding-mode = "modern";
        forwarding-secret-file = "forwarding.secret";

        # announce-forge = true;

        servers = {
          smp = "10.0.0.66:25566";
          speedrun = "10.0.0.66:25567";
          lobby = "10.0.0.66:25568";
          try = ["lobby"];
        };

        "forced-hosts" = {};
      };

      files."plugins/LuckPerms/config.conf" = {
        format = pkgs.formats.json {};
        value = {
          server = "proxy";
          storage-method = "postgresql";
          data = {
            address = "10.0.0.66:5432";
            database = "luckperms";
            username = "minecraft";
            password = "hbhbhb";
            pool-settings = {
              maximum-pool-size = 10;
            };
          };
          messaging-service = "pluginmsg";
        };
      };

      jvmOpts = "-Dluckperms.base-directory=plugins/LuckPerms";
    };
  };
}
