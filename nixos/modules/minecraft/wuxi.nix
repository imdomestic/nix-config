# wuxi-mc.nix
{
  lib,
  pkgs,
  inputs,
  ...
}: {
  services.minecraft-servers = let
    forwardingSecret = "hbhbhb";
    secretFile = pkgs.runCommand "forwarding.secret" {} "echo -n '${forwardingSecret}' > $out";
  in {
    enable = true;
    eula = true;

    servers.proxy = {
      enable = true;
      package = pkgs.velocityServers.velocity; # 最新 velocity :contentReference[oaicite:14]{index=14}
      openFirewall = false;

      symlinks."forwarding.secret" = secretFile;

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
        sha256 = "sha256-EZ4g5MfPcORMOfvbNCkKD2XNDIi1iIztOoZtERRS8cc=";
      };

      symlinks."plugins/Ambassador.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/cOj6YqJM/versions/YeQbhgna/Ambassador-Velocity-1.4.5-all.jar";
        sha256 = "sha256-fFemScOUhnLL7zWjuqj3OwRqxQnqj/pu4wCIkNNvLBc=";
      };

      symlinks."plugins/SkinsRestorer.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/TsLS8Py5/versions/gtqGepWi/SkinsRestorer.jar";
        sha256 = "sha256-MKDGPE9Y+Sugpem07LaT8u2AlnSjKYg8DEOzcLl0P3I=";
      };

      symlinks."plugins/TAB.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/gG7VFbG0/versions/lhpBZZBR/TAB%20v5.4.0.jar";
        sha256 = "sha256-hwHDVkEf2VECt/OSa+FKy146XLqqRNLX2ymOMN/WI9I=";
      };

      symlinks."plugins/VelocityScoreboardAPI.jar" = pkgs.fetchurl {
        url = "https://github.com/NEZNAMY/VelocityScoreboardAPI/releases/download/1.1.6/VelocityScoreboardAPI.v1.1.6.jar";
        sha256 = "sha256-QXglwvheLu+hmgFvMCAaDKks5seO6z483wMp1Vnky68=";
      };

      symlinks."plugins/Velocircon.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/KkmSfl3v/versions/fSM522rY/Velocircon-1.0.5.jar";
        sha256 = "sha256-atXQb3DEPRNDzFq9XUrhUcmGth3GTXvlt95mqWs7fsA=";
      };

      symlinks."plugins/CMIV.jar" = pkgs.fetchurl {
        url = "https://www.zrips.net/cmiv/download.php?file=CMIV-1.0.2.3.jar";
        sha256 = "sha256-fr2zRVNK/aX8OioT3ezKdNyWxpdBXO2epPciQYaNkyc=";
      };

      # symlinks."plugins/TNEV.jar" = pkgs.fetchurl {
      #   url = "https://cdn.modrinth.com/data/bZ4eSWf0/versions/prNGjbjv/TNE-VelocityCore-0.1.2.8-Release-1.jar";
      #   sha256 = "";
      # };

      files."plugins/Velocircon/rcon.yml" = {
        format = pkgs.formats.yaml {};
        value = {
          enable = true;
          host = "0.0.0.0";
          port = "25575";
          password = "hbhbhb";
        };
      };

      files."plugins/tab/config.yml" = ./tab-velocity-config.yml;

      # velocity.toml：关键几项写上即可
      files."velocity.toml".value = {
        config-version = "2.7"; # 默认配置里有这个字段 :contentReference[oaicite:16]{index=16}
        bind = "0.0.0.0:25565";
        motd = "Velocity Proxy";
        show-max-players = 100000;
        force-key-authentication = false;
        online-mode = false;

        player-info-forwarding-mode = "modern";
        forwarding-secret-file = "forwarding.secret";

        # announce-forge = true;

        advanced = {
          haproxy-protocol = true;
        };

        servers = {
          speedrun = "10.0.0.66:25567";
          lobby = "10.0.0.66:25568";
          snk = "10.0.0.66:25570";
          ftb = "10.0.0.66:25571";
          try = ["lobby"];
        };

        "forced-hosts" = {
          "snk.imdomestic.com" = ["snk"];
        };
      };

      files."plugins/LuckPerms/config.conf" = {
        format = pkgs.formats.json {};
        value = {
          server = "proxy";
          storage-method = "postgresql";
          allow-invalid-usernames = true;
          use-server-uuid-cache = false;
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

      files."plugins/SkinsRestorer/Config.yml" = {
        format = pkgs.formats.yaml {};
        value = {
          Storage = {
            Type = "postgresql";
            Address = "10.0.0.66:5432";
            Database = "luckperms";
            Username = "minecraft";
            Password = "hbhbhb";
          };
        };
      };

      jvmOpts = "-Xmx512M -Dluckperms.base-directory=plugins/LuckPerms";
    };

    servers.lobby = {
      enable = true;
      package = pkgs.paperServers.paper-1_21_1;
      serverProperties = {
        server-port = 25568;
        server-ip = "10.0.0.66"; # 只监听 WireGuard 内网
        online-mode = false; # 必须关闭，交给 Velocity 处理
        allow-nether = false; # 大厅通常不需要地狱
        generate-structures = false;
        spawn-protection = 999; # 保护出生点
        enable-rcon = true;
        enforce-secure-profile = false;
        "rcon.password" = "hbhbhb";
        "rcon.port" = 25578;
      };
      jvmOpts = "-Xms2G -Xmx4G";

      symlinks."plugins/LuckPerms.jar" = pkgs.fetchurl {
        url = "https://download.luckperms.net/1610/bukkit/loader/LuckPerms-Bukkit-5.5.21.jar";
        sha256 = "sha256-asG+JVgKKxyKnS/eYATV3Ilpn/R+La3nfHszG8pgIGE=";
      };

      # symlinks."plugins/EssentialsX.jar" = pkgs.fetchurl {
      #   url = "https://github.com/EssentialsX/Essentials/releases/download/2.21.2/EssentialsX-2.21.2.jar";
      #   sha256 = "sha256-C3WQJvAvPFR8MohvNmbbPB+Uz/c+FBrlZIMT/Q0L38Y=";
      # };
      #
      # symlinks."plugins/EssentialsXSpawn.jar" = pkgs.fetchurl {
      #   url = "https://github.com/EssentialsX/Essentials/releases/download/2.21.2/EssentialsXSpawn-2.21.2.jar";
      #   sha256 = "sha256-CnobRGh7bZ2E+vQkNgsuBKKr9FDi2ZmPJ7K6RwZ0a4Y=";
      # };

      symlinks."plugins/CMILib.jar" = pkgs.fetchurl {
        url = "https://www.zrips.net/CMILib/CMILib1.5.8.1.jar";
        sha256 = "sha256-W9+mSxAB1W4XdxakC08zpMmRoDeWn+xhBRMxQsJhyLI=";
      };

      symlinks."plugins/CMI.jar" = "${inputs.wg-config.outPath}/CMI.jar";

      symlinks."plugins/VaultUnlocked.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/ayRaM8J7/versions/hWDrazHd/VaultUnlocked-2.17.0.jar";
        sha256 = "sha256-feIkNsA49QBg8qpOpfSv01MCDkViiN6gOJahGrqhy4c=";
      };
      symlinks."plugins/PlaceholderAPI.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/lKEzGugV/versions/sn9LYZkM/PlaceholderAPI-2.11.7.jar";
        sha256 = "sha256-9aTqcYuqq2EYz+jzmD6jpWYK8e6FcjYBgqPRttvy610=";
      };
      symlinks."plugins/SkinsRestorer.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/TsLS8Py5/versions/gtqGepWi/SkinsRestorer.jar";
        sha256 = "sha256-MKDGPE9Y+Sugpem07LaT8u2AlnSjKYg8DEOzcLl0P3I=";
      };
      symlinks."plugins/TAB-Bridge.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/kG3hVbBX/versions/cOXgQQKY/TAB-Bridge%20v6.2.0.jar";
        sha256 = "sha256-7L2IOopc3SOQ7fnCQbVVJTB1vWc9NQcXgt+kMn82BnE=";
      };
      symlinks."plugins/CMIEInjector.jar" = pkgs.fetchurl {
        url = "https://zrips.net/cmii/download.php?file=CMIEInjector1.0.2.4.jar";
        sha256 = "sha256-ONRNpw4Pw4qgRIDCuzZeit+F3RYKPw82z9gAaD5fukI=";
      };

      # files."spigot.yml".value = {
      #   settings = {
      #     bungeecord = true;
      #   };
      # };

      files."config/paper-global.yml".value = {
        proxies = {
          velocity = {
            enabled = true;
            # online-mode = true;
            secret = "hbhbhb";
          };
        };
      };

      files."plugins/SkinsRestorer/Config.yml" = {
        format = pkgs.formats.yaml {};
        value = {
          Storage = {
            Type = "postgresql";
            Address = "10.0.0.66:5432";
            Database = "luckperms";
            Username = "minecraft";
            Password = "hbhbhb";
          };
        };
      };

      files."plugins/LuckPerms/config.yml" = {
        format = pkgs.formats.yaml {};
        value = {
          server = "lobby";
          storage-method = "postgresql";
          allow-invalid-usernames = true;
          use-server-uuid-cache = false;
          unloaded-user-action = "warn";
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

      files."plugins/CMI/Settings/Chat.yml" = ./cmi-Chat.yml;
      files."plugins/CMI/Settings/DataBaseInfo.yml" = ./cmi-DataBaseInfo.yml;
      files."plugins/CMI/config.yml" = ./cmi-config.yaml;
    };

    servers.survival = {
      enable = false;
      package = pkgs.fabricServers.fabric-1_21_1;

      serverProperties = {
        server-ip = "10.0.0.66";
        server-port = 25566;
        online-mode = false;
        motd = "SMP 1.21.1";
        enable-rcon = true;
        "rcon.password" = "hbhbhb";
        "rcon.port" = 25576;
      };

      # symlinks = {
      #   "mods/FabricAPI.jar" = pkgs.fetchurl {
      #     url = "https://cdn.modrinth.com/data/P7dR8mSH/versions/5oK85X7C/fabric-api-0.140.0%2B1.21.11.jar";
      #     sha512 = "f33d3aa6d4da877975eb0f814f9ac8c02f9641e0192402445912ddab43269efcc685ef14d59fd8ee53deb9b6ff4521442e06e1de1fd1284b426711404db5350b";
      #   };
      #   "mods/FabricProxyLite.jar" = pkgs.fetchurl {
      #     url = "https://cdn.modrinth.com/data/8dI2tmqs/versions/nR8AIdvx/FabricProxy-Lite-2.11.0.jar";
      #     sha512 = "c2e1d9279f6f19a561f934b846540b28a033586b4b419b9c1aa27ac43ffc8fad2ce60e212a15406e5fa3907ff5ecbe5af7a5edb183a9ee6737a41e464aec1375";
      #   };
      #   "mods/LuckPerms.jar" = pkgs.fetchurl {
      #     url = "https://download.luckperms.net/1610/fabric/LuckPerms-Fabric-5.5.21.jar";
      #     sha256 = "sha256-mNsvmLvat0o2x06LQuX18V5pkQUfSipV9N2rShDOEwQ=";
      #   };
      #   "mods/Lithium.jar" = pkgs.fetchurl {
      #     url = "https://cdn.modrinth.com/data/gvQqBUqZ/versions/4DdLmtyz/lithium-fabric-0.21.1%2Bmc1.21.11.jar";
      #     sha256 = "sha256-bPXo/SctwzIGa2XLXC6KFrmfueg92Hu5upxZU+LPUw4=";
      #   };
      #   "mods/TAB-Bridge" = pkgs.fetchurl {
      #     url = "https://cdn.modrinth.com/data/kG3hVbBX/versions/cOXgQQKY/TAB-Bridge%20v6.2.0.jar";
      #     sha256 = "sha256-7L2IOopc3SOQ7fnCQbVVJTB1vWc9NQcXgt+kMn82BnE=";
      #   };
      # };

      # files."config/FabricProxy-Lite.toml".value = {
      #   secret = "hbhbhb";
      #   disconnectMessage = "Please connect via the proxy (Velocity).";
      # };
      #
      # files."config/luckperms/luckperms.conf" = {
      #   format = pkgs.formats.json {};
      #   value = {
      #     server = "speedrun";
      #     storage-method = "postgresql";
      #     allow-invalid-usernames = true;
      #     use-server-uuid-cache = false;
      #     skip-username-check-on-login = true;
      #     unloaded-user-action = "warn";
      #     data = {
      #       address = "10.0.0.66:5432";
      #       database = "luckperms";
      #       username = "minecraft";
      #       password = "hbhbhb";
      #       pool-settings = {
      #         maximum-pool-size = 10;
      #       };
      #     };
      #     messaging-service = "pluginmsg";
      #   };
      # };

      # jvmOpts = "-Xms4G -Xmx8G -Dluckperms.base-directory=config/luckperms";

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
      package = pkgs.paperServers.paper-1_21_11;

      serverProperties = {
        server-ip = "10.0.0.66";
        server-port = 25567;
        online-mode = false;
        motd = "SpeedRun 1.21.11";
        enforce-secure-profile = false;
        enable-rcon = true;
        "rcon.password" = "hbhbhb";
        "rcon.port" = 25577;
      };

      symlinks."plugins/LuckPerms.jar" = pkgs.fetchurl {
        url = "https://download.luckperms.net/1610/bukkit/loader/LuckPerms-Bukkit-5.5.21.jar";
        sha256 = "sha256-asG+JVgKKxyKnS/eYATV3Ilpn/R+La3nfHszG8pgIGE=";
      };

      symlinks."plugins/CMILib.jar" = pkgs.fetchurl {
        url = "https://www.zrips.net/CMILib/CMILib1.5.8.1.jar";
        sha256 = "sha256-W9+mSxAB1W4XdxakC08zpMmRoDeWn+xhBRMxQsJhyLI=";
      };

      symlinks."plugins/CMI.jar" = "${inputs.wg-config.outPath}/CMI.jar";

      symlinks."plugins/VaultUnlocked.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/ayRaM8J7/versions/hWDrazHd/VaultUnlocked-2.17.0.jar";
        sha256 = "sha256-feIkNsA49QBg8qpOpfSv01MCDkViiN6gOJahGrqhy4c=";
      };
      symlinks."plugins/PlaceholderAPI.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/lKEzGugV/versions/sn9LYZkM/PlaceholderAPI-2.11.7.jar";
        sha256 = "sha256-9aTqcYuqq2EYz+jzmD6jpWYK8e6FcjYBgqPRttvy610=";
      };
      symlinks."plugins/SkinsRestorer.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/TsLS8Py5/versions/gtqGepWi/SkinsRestorer.jar";
        sha256 = "sha256-MKDGPE9Y+Sugpem07LaT8u2AlnSjKYg8DEOzcLl0P3I=";
      };
      symlinks."plugins/TAB-Bridge.jar" = pkgs.fetchurl {
        url = "https://cdn.modrinth.com/data/kG3hVbBX/versions/cOXgQQKY/TAB-Bridge%20v6.2.0.jar";
        sha256 = "sha256-7L2IOopc3SOQ7fnCQbVVJTB1vWc9NQcXgt+kMn82BnE=";
      };
      symlinks."plugins/CMIEInjector.jar" = pkgs.fetchurl {
        url = "https://zrips.net/cmii/download.php?file=CMIEInjector1.0.2.4.jar";
        sha256 = "sha256-ONRNpw4Pw4qgRIDCuzZeit+F3RYKPw82z9gAaD5fukI=";
      };

      files."config/paper-global.yml".value = {
        proxies = {
          velocity = {
            enabled = true;
            # online-mode = true;
            secret = "hbhbhb";
          };
        };
      };

      files."plugins/SkinsRestorer/Config.yml" = {
        format = pkgs.formats.yaml {};
        value = {
          Storage = {
            Type = "postgresql";
            Address = "10.0.0.66:5432";
            Database = "luckperms";
            Username = "minecraft";
            Password = "hbhbhb";
          };
        };
      };

      files."plugins/LuckPerms/config.yml" = {
        format = pkgs.formats.yaml {};
        value = {
          server = "lobby";
          storage-method = "postgresql";
          allow-invalid-usernames = true;
          use-server-uuid-cache = false;
          unloaded-user-action = "warn";
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

      files."plugins/CMI/Settings/Chat.yml" = ./cmi-Chat.yml;
      files."plugins/CMI/Settings/DataBaseInfo.yml" = ./cmi-DataBaseInfo.yml;
      files."plugins/CMI/config.yml" = ./cmi-config.yaml;
      jvmOpts = "-Xms4G -Xmx8G";
    };

    servers.duel = let
      modpackSource = "/srv/minecraft/duel";
      customForgePackage = pkgs.writeShellScriptBin "minecraft-server" ''
        exec ${pkgs.temurin-bin-17}/bin/java \
          @user_jvm_args.txt \
          @libraries/net/minecraftforge/forge/1.18.2-40.2.21/unix_args.txt \
          "$@"
      '';
    in {
      enable = false;
      package = customForgePackage;
      serverProperties = {
        server-ip = "10.0.0.66";
        server-port = 25569;
        online-mode = false;
        motd = "Forge 1.18.2 Duel Pack";
        enable-rcon = true;
        "rcon.password" = "hbhbhb";
        "rcon.port" = 25579;
      };

      symlinks = {
        "mods" = "${modpackSource}/mods";
        "config" = "${modpackSource}/config";
        "defaultconfigs" = "${modpackSource}/defaultconfigs";
        "kubejs" = "${modpackSource}/kubejs";
        "scripts" = "${modpackSource}/scripts";
        "local" = "${modpackSource}/local";
        "patchouli_books" = "${modpackSource}/patchouli_books";
        "fancymenu_data" = "${modpackSource}/fancymenu_data";
        "custom trades" = "${modpackSource}/'custom trades'";
        "Ocean_Towers" = "${modpackSource}/Ocean_Towers";
        "Land_Towers" = "${modpackSource}/Land_Towers";

        "mods/LuckPerms-Forge.jar" = pkgs.fetchurl {
          url = "https://download.luckperms.net/1610/forge/loader/LuckPerms-Forge-5.5.21.jar";
          sha256 = "sha256-F8URU+EkhENm65ygohaGfdvTs8N9JUDQ5IeXfDxm+mM=";
        };
      };

      files."config/luckperms/luckperms.conf" = {
        format = pkgs.formats.json {};
        value = {
          server = "modpack";
          storage-method = "postgresql";
          online-mode = false;
          allow-invalid-usernames = true;
          data = {
            address = "10.0.0.66:5432";
            database = "luckperms";
            username = "minecraft";
            password = "hbhbhb";
          };
          messaging-service = "pluginmsg";
        };
      };
      jvmOpts = "-Xms6G -Xmx12G -Dluckperms.base-directory=config/luckperms";
    };
  };
}
