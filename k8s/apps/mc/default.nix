# 用 tank 上的旧服存档（/data/srv/minecraft）搭的测试网络：Velocity + 大厅 + bingo。
#
# 目的是先验证集群、存储、网络和 GitOps 这条链；大厅和 bingo 之后会换成 Agones
# Fleet，镜像改成 CI 构建的。旧服的定义见 nixos/modules/minecraft/wuxi.nix。
{lib, ...}: let
  images = {
    server = "itzg/minecraft-server:2026.9.2-java21";
    # Velocity 4.2 要 Java 25。
    proxy = "itzg/mc-proxy:2026.10.0-java25";
    seed = "busybox:1.37.0";
  };

  forwardingSecret.secretKeyRef = {
    name = "velocity-forwarding";
    key = "secret";
  };

  # 和旧服一样，跨版本兼容由代理上的 Via 负责。
  viaPlugins = [
    "https://github.com/ViaVersion/ViaVersion/releases/download/5.12.0/ViaVersion-5.12.0.jar"
    "https://github.com/ViaVersion/ViaBackwards/releases/download/5.12.0/ViaBackwards-5.12.0.jar"
    "https://github.com/ViaVersion/ViaRewind/releases/download/4.2.0/ViaRewind-4.2.0.jar"
  ];

  bingoMods = [
    "https://cdn.modrinth.com/data/P7dR8mSH/versions/DdVHbeR1/fabric-api-0.141.1%2B1.21.11.jar"
    "https://cdn.modrinth.com/data/8dI2tmqs/versions/nR8AIdvx/FabricProxy-Lite-2.11.0.jar"
    "https://cdn.modrinth.com/data/gvQqBUqZ/versions/gl30uZvp/lithium-fabric-0.21.2%2Bmc1.21.11.jar"
    "https://cdn.modrinth.com/data/mHeNceaH/versions/Vb6yPYhc/bingo-2.9.7%2Bmc1.21.11.jar"
  ];

  # 旧服是离线模式，存档里的玩家数据按离线 UUID 存。测试期间保持一致，只在 tailnet 内可达。
  velocityToml = ''
    config-version = "2.7"
    bind = "0.0.0.0:25565"
    motd = "<#09add3>imdomestic · tank 测试"
    show-max-players = 100
    online-mode = false
    force-key-authentication = false
    prevent-client-proxy-connections = false
    player-info-forwarding-mode = "modern"
    # 实际的密钥来自环境变量 VELOCITY_FORWARDING_SECRET，Velocity 优先读它。
    forwarding-secret-file = "forwarding.secret"
    announce-forge = false
    kick-existing-players = false
    ping-passthrough = "DISABLED"
    enable-player-address-logging = true

    [servers]
    lobby = "lobby:25565"
    bingo = "bingo:25565"
    try = ["lobby"]

    [forced-hosts]

    [advanced]
    compression-threshold = 256
    compression-level = -1
    login-ratelimit = 3000
    connection-timeout = 5000
    read-timeout = 30000
    haproxy-protocol = false
    tcp-fast-open = false
    bungee-plugin-message-channel = true
    show-ping-requests = false
    failover-on-unexpected-server-disconnect = true
    announce-proxy-commands = true
    log-command-executions = false
    log-player-connections = true
    accepts-transfers = false

    [query]
    enabled = false
    port = 25565
    map = "Velocity"
    show-plugins = false
  '';

  # itzg 会把 /config 同步到 /data/config，再把 ''${CFG_*} 换成同名环境变量。
  paperGlobal = ''
    proxies:
      velocity:
        enabled: true
        online-mode: false
        secret: ''${CFG_FORWARDING_SECRET}
  '';

  # 一台后端：StatefulSet + 同名 Service。第一次启动时把旧存档拷进 PVC。
  mkServer = name: {
    env,
    memoryLimit,
    extraVolumeMounts ? {},
    extraVolumes ? {},
  }: {
    statefulSets.${name}.spec = {
      serviceName = name;
      replicas = 1;
      selector.matchLabels.app = name;
      template = {
        metadata.labels.app = name;
        spec = {
          # 原存档只读挂载，拷一次后留下标记文件，之后的重启不会再覆盖。
          initContainers.seed = {
            image = images.seed;
            command = ["sh" "-c" "[ -e /data/.seeded ] || { cp -a /seed/. /data/ && touch /data/.seeded; }"];
            volumeMounts = {
              "/data".name = "data";
              "/seed" = {
                name = "seed";
                readOnly = true;
              };
            };
          };
          containers.server = {
            image = images.server;
            env =
              {
                EULA.value = "TRUE";
                ONLINE_MODE.value = "FALSE";
                ENFORCE_SECURE_PROFILE.value = "FALSE";
                # 堆交给 JVM 按容器上限算，留出堆外内存。
                MEMORY.value = "";
                JVM_XX_OPTS.value = "-XX:MaxRAMPercentage=75";
              }
              // env;
            ports.minecraft.containerPort = 25565;
            volumeMounts = {"/data".name = "data";} // extraVolumeMounts;
            resources = {
              requests.memory = memoryLimit;
              limits.memory = memoryLimit;
            };
            readinessProbe = {
              exec.command = ["mc-health"];
              initialDelaySeconds = 30;
              periodSeconds = 10;
            };
          };
          volumes =
            {
              seed.hostPath = {
                path = "/data/srv/minecraft/${name}";
                type = "Directory";
              };
            }
            // extraVolumes;
        };
      };
      volumeClaimTemplates = [
        {
          metadata.name = "data";
          spec = {
            accessModes = ["ReadWriteOnce"];
            resources.requests.storage = "10Gi";
          };
        }
      ];
    };

    services.${name}.spec = {
      selector.app = name;
      ports.minecraft = {
        port = 25565;
        targetPort = 25565;
      };
    };
  };
in {
  applications.mc = {
    namespace = "mc";
    # 命名空间和 velocity-forwarding 密钥一起由 nixos/hosts/tank/k3s.nix 建。
    createNamespace = false;

    resources = lib.mkMerge [
      (mkServer "lobby" {
        memoryLimit = "3Gi";
        env = {
          TYPE.value = "PAPER";
          VERSION.value = "1.21.1";
          PAPER_BUILD.value = "133";
          MOTD.value = "lobby";
          ALLOW_NETHER.value = "FALSE";
          SPAWN_PROTECTION.value = "999";
          CFG_FORWARDING_SECRET.valueFrom = forwardingSecret;
        };
        extraVolumeMounts."/config".name = "config";
        extraVolumes.config.configMap.name = "lobby-config";
      })

      (mkServer "bingo" {
        memoryLimit = "4Gi";
        env = {
          TYPE.value = "FABRIC";
          VERSION.value = "1.21.11";
          FABRIC_LOADER_VERSION.value = "0.19.5";
          MOTD.value = "bingo 1.21.11";
          MODS.value = lib.concatStringsSep "," bingoMods;
          FABRIC_PROXY_SECRET.valueFrom = forwardingSecret;
        };
      })

      {
        configMaps.lobby-config.data."paper-global.yml" = paperGlobal;
        configMaps.velocity.data."velocity.toml" = velocityToml;

        deployments.proxy.spec = {
          replicas = 1;
          selector.matchLabels.app = "proxy";
          template = {
            metadata.labels.app = "proxy";
            spec = {
              containers.proxy = {
                image = images.proxy;
                env = {
                  TYPE.value = "VELOCITY";
                  VELOCITY_VERSION.value = "4.2.0";
                  VELOCITY_BUILD_ID.value = "30";
                  MEMORY.value = "512m";
                  SERVER_PORT.value = "25565";
                  PLUGINS.value = lib.concatStringsSep "," viaPlugins;
                  VELOCITY_FORWARDING_SECRET.valueFrom = forwardingSecret;
                };
                ports.minecraft.containerPort = 25565;
                volumeMounts."/config".name = "config";
                resources = {
                  requests.memory = "768Mi";
                  limits.memory = "768Mi";
                };
              };
              volumes.config.configMap.name = "velocity";
            };
          };
        };

        # k3s 自带的 servicelb 会在 tank 上占住 25565，tailnet 和局域网都能连。
        services.proxy.spec = {
          type = "LoadBalancer";
          selector.app = "proxy";
          ports.minecraft = {
            port = 25565;
            targetPort = 25565;
          };
        };
      }
    ];
  };
}
