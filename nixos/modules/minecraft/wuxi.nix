# wuxi-mc.nix
{ lib, pkgs, inputs, ... }:
let
  forwardingSecret = "hbhbhb";

  mcVersion = "1.21.1";
  serverVersion = lib.replaceStrings ["."] ["_"] "fabric-${mcVersion}";

  # 用 nix-minecraft 的 nix-modrinth-prefetch 生成 fetchurl（见后面）:contentReference[oaicite:6]{index=6}
  fabricApi = pkgs.fetchurl {
    url = "https://cdn.modrinth.com/data/P7dR8mSH/versions/m6zu1K31/fabric-api-0.116.7%2B1.21.1.jar";
    sha512 = "把 sha512 放这里";
  };
  fabricProxyLite = pkgs.fetchurl {
    url = "https://cdn.modrinth.com/data/8dI2tmqs/versions/KqB3UA0q/FabricProxy-Lite-2.10.1.jar";
    sha512 = "把 sha512 放这里";
  };
in {
  services.minecraft-servers = {
    enable = true;
    eula = true;

    servers.survival = {
      enable = true;
      package = pkgs.fabricServers.${serverVersion};

      serverProperties = {
        server-ip = "10.0.0.66";
        server-port = 25566;
        online-mode = false;
        motd = "Wuxi Fabric SMP (behind Velocity)";
      };

      # mods 目录：symlink 一个 folder 进去（linkFarmFromDrvs 是常用写法）:contentReference[oaicite:8]{index=8}
      symlinks.mods = pkgs.linkFarmFromDrvs "mods" (builtins.attrValues {
        FabricAPI = fabricApi;
        FabricProxyLite = fabricProxyLite;
      });

      # FabricProxy-Lite 配置：写 secret 即可（toml 可用 .value 自动生成）:contentReference[oaicite:9]{index=9}
      files."config/FabricProxy-Lite.toml".value = {
        secret = forwardingSecret;
        disconnectMessage = "Please connect via the proxy (Velocity).";
        # 其它 hack* 先不动，默认值就行（需要再开）
      };

      jvmOpts = "-Xms4G -Xmx12G";
      openFirewall = false; # 我们手动只放 wg0（见下面）
    };
  };
}

