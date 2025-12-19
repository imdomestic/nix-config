{ pkgs, ... }:
let
  forwardingSecret = "hbhbhb";
in {
  services.minecraft-servers = {
    enable = true;
    eula = true;

    servers.proxy = {
      enable = true;
      package = pkgs.velocityServers.velocity; # 最新 velocity :contentReference[oaicite:14]{index=14}
      openFirewall = false;

      # secret 文件：用 txt 生成最省事（nix-minecraft 支持 txt 自动生成）:contentReference[oaicite:15]{index=15}
      files."forwarding.secret.txt".value = forwardingSecret;

      # velocity.toml：关键几项写上即可
      files."velocity.toml".value = {
        config-version = "2.7"; # 默认配置里有这个字段 :contentReference[oaicite:16]{index=16}
        bind = "0.0.0.0:25565";
        motd = "My Velocity Proxy";
        show-max-players = 100;
        online-mode = false;

        player-info-forwarding-mode = "modern";
        forwarding-secret-file = "forwarding.secret.txt";

        announce-forge = true;

        servers = {
          smp = "10.0.0.66:25566";
        };
        try = [ "smp" ];
      };
    };
  };
}

