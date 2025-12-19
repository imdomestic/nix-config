# wuxi-mc.nix
{
  lib,
  pkgs,
  inputs,
  ...
}: {
  services.minecraft-servers = {
    enable = true;
    eula = true;
    dataDir = "/data/nas/public/minecraft";

    servers.lobby = {
      enable = true;
      package = pkgs.paperServers.paper-1_21_11;
      serverProperties = {
        server-port = 25568;
        server-ip = "10.0.0.66"; # 只监听 WireGuard 内网
        online-mode = false; # 必须关闭，交给 Velocity 处理
        allow-nether = false; # 大厅通常不需要地狱
        generate-structures = false;
        spawn-protection = 999; # 保护出生点
      };
      jvmOpts = "-Xms2G -Xmx4G";
      files."config/paper-global.yml".value = {
        proxies = {
          velocity = {
            enabled = true;
            # online-mode = true;
            secret = "hbhbhb";
          };
        };
      };
    };

    servers.survival = {
      enable = true;
      package = pkgs.fabricServers.fabric-1_21_1;

      serverProperties = {
        server-ip = "10.0.0.66";
        server-port = 25566;
        online-mode = false;
        motd = "SMP 1.21.1";
      };

      symlinks.mods = pkgs.linkFarmFromDrvs "mods" (builtins.attrValues {
        FabricAPI = pkgs.fetchurl {
          url = "https://cdn.modrinth.com/data/P7dR8mSH/versions/m6zu1K31/fabric-api-0.116.7%2B1.21.1.jar";
          sha512 = "0d7bf97e516cfdb742d7e37a456ed51f96c46eac060c0f2b80338089670b38aba2f7a9837e5e07a6bdcbf732e902014fb1202f6e18e00d6d2b560a84ddf9c024";
        };
        FabricProxyLite = pkgs.fetchurl {
          url = "https://cdn.modrinth.com/data/8dI2tmqs/versions/KqB3UA0q/FabricProxy-Lite-2.10.1.jar";
          sha512 = "9c0c1d44ba27ed3483bb607f95441bea9fb1c65be26aa5dc0af743167fb7933623ba6129344738b084056aef7cb5a7db0db477348d07672d5c67a2e1204e9c94";
        };
      });

      files."config/FabricProxy-Lite.toml".value = {
        secret = "hbhbhb";
        disconnectMessage = "Please connect via the proxy (Velocity).";
      };

      jvmOpts = "-Xms4G -Xmx8G";
    };

    servers.speedrun = {
      enable = true;
      package = pkgs.fabricServers.fabric-1_21_11;

      serverProperties = {
        server-ip = "10.0.0.66";
        server-port = 25567;
        online-mode = false;
        motd = "SpeedRun 1.21.22";
      };

      symlinks.mods = pkgs.linkFarmFromDrvs "mods" (builtins.attrValues {
        FabricAPI = pkgs.fetchurl {
          url = "https://cdn.modrinth.com/data/P7dR8mSH/versions/5oK85X7C/fabric-api-0.140.0%2B1.21.11.jar";
          sha512 = "f33d3aa6d4da877975eb0f814f9ac8c02f9641e0192402445912ddab43269efcc685ef14d59fd8ee53deb9b6ff4521442e06e1de1fd1284b426711404db5350b";
        };
        FabricProxyLite = pkgs.fetchurl {
          url = "https://cdn.modrinth.com/data/8dI2tmqs/versions/nR8AIdvx/FabricProxy-Lite-2.11.0.jar";
          sha512 = "c2e1d9279f6f19a561f934b846540b28a033586b4b419b9c1aa27ac43ffc8fad2ce60e212a15406e5fa3907ff5ecbe5af7a5edb183a9ee6737a41e464aec1375";
        };
      });

      files."config/FabricProxy-Lite.toml".value = {
        secret = "hbhbhb";
        disconnectMessage = "Please connect via the proxy (Velocity).";
      };

      jvmOpts = "-Xms4G -Xmx8G";
    };
  };
}
