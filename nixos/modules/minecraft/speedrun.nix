# wuxi-mc.nix
{
  lib,
  pkgs,
  inputs,
  ...
}: let
  forwardingSecret = "hbhbhb";

  mcVersion = "1.21.11";
  serverVersion = lib.replaceStrings ["."] ["_"] "fabric-${mcVersion}";

  # 用 nix-minecraft 的 nix-modrinth-prefetch 生成 fetchurl（见后面）:contentReference[oaicite:6]{index=6}
  fabricApi = pkgs.fetchurl {
    url = "https://cdn.modrinth.com/data/P7dR8mSH/versions/5oK85X7C/fabric-api-0.140.0%2B1.21.11.jar";
    sha512 = "f33d3aa6d4da877975eb0f814f9ac8c02f9641e0192402445912ddab43269efcc685ef14d59fd8ee53deb9b6ff4521442e06e1de1fd1284b426711404db5350b";
  };
  fabricProxyLite = pkgs.fetchurl {
    url = "https://cdn.modrinth.com/data/8dI2tmqs/versions/nR8AIdvx/FabricProxy-Lite-2.11.0.jar";
    sha512 = "c2e1d9279f6f19a561f934b846540b28a033586b4b419b9c1aa27ac43ffc8fad2ce60e212a15406e5fa3907ff5ecbe5af7a5edb183a9ee6737a41e464aec1375";
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
        server-port = 25567;
        online-mode = false;
        motd = "SpeedRun";
      };

      symlinks.mods = pkgs.linkFarmFromDrvs "mods" (builtins.attrValues {
        FabricAPI = fabricApi;
        FabricProxyLite = fabricProxyLite;
      });

      files."config/FabricProxy-Lite.toml".value = {
        secret = forwardingSecret;
        disconnectMessage = "Please connect via the proxy (Velocity).";
      };

      jvmOpts = "-Xms4G -Xmx12G";
    };
  };
}
