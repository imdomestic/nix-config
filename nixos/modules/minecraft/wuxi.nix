# wuxi-mc.nix
{
  lib,
  pkgs,
  inputs,
  ...
}: let
  forwardingSecret = "hbhbhb";

  mcVersion = "1.21.1";
  serverVersion = lib.replaceStrings ["."] ["_"] "fabric-${mcVersion}";

  # 用 nix-minecraft 的 nix-modrinth-prefetch 生成 fetchurl（见后面）:contentReference[oaicite:6]{index=6}
  fabricApi = pkgs.fetchurl {
    url = "https://cdn.modrinth.com/data/P7dR8mSH/versions/m6zu1K31/fabric-api-0.116.7%2B1.21.1.jar";
    sha512 = "0d7bf97e516cfdb742d7e37a456ed51f96c46eac060c0f2b80338089670b38aba2f7a9837e5e07a6bdcbf732e902014fb1202f6e18e00d6d2b560a84ddf9c024";
  };
  fabricProxyLite = pkgs.fetchurl {
    url = "https://cdn.modrinth.com/data/8dI2tmqs/versions/KqB3UA0q/FabricProxy-Lite-2.10.1.jar";
    sha512 = "9c0c1d44ba27ed3483bb607f95441bea9fb1c65be26aa5dc0af743167fb7933623ba6129344738b084056aef7cb5a7db0db477348d07672d5c67a2e1204e9c94";
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
