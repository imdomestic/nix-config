# 运营网络：Velocity（带路由插件）+ 大厅 Fleet + bingo。
#
# 大厅是 Agones Fleet，由 minecraft/agones-paper 插件上报状态，Velocity 上的
# minecraft/velocity-router 按 GameServer 动态注册后端。bingo 还是用旧存档的 StatefulSet，
# 之后再换。旧服的定义见 nixos/modules/minecraft/wuxi.nix。
{lib, ...}: let
  tag = import ../../../minecraft/image-tag.nix;

  images = {
    # CI（.github/workflows/k8s.yml）构建，tag 是 minecraft/ 的内容哈希。
    lobby = "ghcr.io/imdomestic/mc-lobby:${tag}";
    proxy = "ghcr.io/imdomestic/mc-proxy:${tag}";
    server = "itzg/minecraft-server:2026.9.2-java21";
    seed = "busybox:1.37.0";
  };

  forwardingSecret.secretKeyRef = {
    name = "velocity-forwarding";
    key = "secret";
  };

  # 和旧服一样，跨版本兼容由代理上的 Via 负责；动态后端的版本由路由插件告诉 Via。
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

  # 旧服是离线模式，存档里的玩家数据按离线 UUID 存。测试期间保持一致，只在 tailnet 和局域网内可达。
  # 大厅不在这里：它是动态后端，由路由插件注册；try 留空，进服时由插件选大厅。
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
    bingo = "bingo:25565"
    try = []

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

  # 大厅存档里只拷世界和管理数据：服务端 jar、库和缓存由 itzg 每次启动时自己准备。
  lobbySeedPaths = [
    "world"
    "world_nether"
    "world_the_end"
    "config"
    "bukkit.yml"
    "spigot.yml"
    "ops.json"
    "whitelist.json"
    "banned-players.json"
    "banned-ips.json"
    "usercache.json"
  ];

  lobbyFleet = {
    apiVersion = "agones.dev/v1";
    kind = "Fleet";
    metadata.name = "lobby";
    # replicas 交给 FleetAutoscaler，这里不写，否则 Argo CD 会和它来回改。
    spec.template = {
      metadata.labels = {
        "mc.imdomestic.com/kind" = "lobby";
        # Paper 1.21.1。
        "mc.imdomestic.com/protocol" = "767";
      };
      spec = {
        container = "server";
        # 不占 hostPort，Velocity 在集群里直连 Pod IP。默认协议是 UDP，MC 要 TCP。
        ports = [
          {
            name = "minecraft";
            portPolicy = "None";
            containerPort = 25565;
            protocol = "TCP";
          }
        ];
        # 每次启动都要下载 Paper，插件启用之前没人 ping。之后插件每秒 ping 一次，
        # 连续 60 秒没有才判 Unhealthy，扛得住 GC 和存盘的卡顿。
        health = {
          initialDelaySeconds = 180;
          periodSeconds = 5;
          failureThreshold = 12;
        };
        lists.players.capacity = 100;
        template.spec = {
          initContainers = [
            {
              name = "seed";
              image = images.seed;
              command = [
                "sh"
                "-c"
                ''
                  for p in ${lib.concatStringsSep " " lobbySeedPaths}; do
                    if [ -e "/seed/$p" ]; then cp -a "/seed/$p" /data/; fi
                  done
                ''
              ];
              volumeMounts = [
                {
                  name = "data";
                  mountPath = "/data";
                }
                {
                  name = "seed";
                  mountPath = "/seed";
                  readOnly = true;
                }
              ];
            }
          ];
          containers = [
            {
              name = "server";
              image = images.lobby;
              env =
                lib.mapAttrsToList (name: value: {inherit name value;}) {
                  EULA = "TRUE";
                  TYPE = "PAPER";
                  VERSION = "1.21.1";
                  PAPER_BUILD = "133";
                  ONLINE_MODE = "FALSE";
                  ENFORCE_SECURE_PROFILE = "FALSE";
                  MOTD = "lobby";
                  ALLOW_NETHER = "FALSE";
                  SPAWN_PROTECTION = "999";
                  MODE = "adventure";
                  # 堆交给 JVM 按容器上限算，留出堆外内存。
                  MEMORY = "";
                  JVM_XX_OPTS = "-XX:MaxRAMPercentage=75";
                  MC_AGONES_MODE = "lobby";
                }
                ++ [
                  {
                    name = "CFG_FORWARDING_SECRET";
                    valueFrom = forwardingSecret;
                  }
                ];
              resources = {
                requests.memory = "3Gi";
                limits.memory = "3Gi";
              };
              volumeMounts = [
                {
                  name = "data";
                  mountPath = "/data";
                }
                {
                  name = "config";
                  mountPath = "/config";
                }
              ];
            }
          ];
          # 大厅不保存玩家改动：每次启动都从旧存档重新拷一份。
          volumes = [
            {
              name = "data";
              emptyDir = {};
            }
            {
              name = "config";
              configMap.name = "lobby-config";
            }
            {
              name = "seed";
              hostPath = {
                path = "/data/srv/minecraft/lobby";
                type = "Directory";
              };
            }
          ];
        };
      };
    };
  };

  # 永远留一台没人的大厅待命：插件让有人的大厅进入 Allocated，缩容只会删 Ready 的。
  lobbyAutoscaler = {
    apiVersion = "autoscaling.agones.dev/v1";
    kind = "FleetAutoscaler";
    metadata.name = "lobby";
    spec = {
      fleetName = "lobby";
      policy = {
        type = "Buffer";
        buffer = {
          bufferSize = 1;
          minReplicas = 1;
          maxReplicas = 3;
        };
      };
      sync = {
        type = "FixedInterval";
        fixedInterval.seconds = 30;
      };
    };
  };

  # 一台带 PVC 的后端：StatefulSet + 同名 Service。第一次启动时把旧存档拷进 PVC。
  mkServer = name: {
    env,
    memoryLimit,
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
                MEMORY.value = "";
                JVM_XX_OPTS.value = "-XX:MaxRAMPercentage=75";
              }
              // env;
            ports.minecraft.containerPort = 25565;
            volumeMounts."/data".name = "data";
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
          volumes.seed.hostPath = {
            path = "/data/srv/minecraft/${name}";
            type = "Directory";
          };
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

    # Fleet 和 FleetAutoscaler 没有 nixidy 的类型定义，原样放进去。
    yamls = map builtins.toJSON [lobbyFleet lobbyAutoscaler];

    resources = lib.mkMerge [
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

        # 路由插件只读 GameServer。
        serviceAccounts.velocity-router = {};
        roles.velocity-router.rules = [
          {
            apiGroups = ["agones.dev"];
            resources = ["gameservers"];
            verbs = ["get" "list" "watch"];
          }
        ];
        roleBindings.velocity-router = {
          roleRef = {
            apiGroup = "rbac.authorization.k8s.io";
            kind = "Role";
            name = "velocity-router";
          };
          subjects = [
            {
              kind = "ServiceAccount";
              name = "velocity-router";
              namespace = "mc";
            }
          ];
        };

        deployments.proxy.spec = {
          replicas = 1;
          selector.matchLabels.app = "proxy";
          template = {
            metadata.labels.app = "proxy";
            spec = {
              serviceAccountName = "velocity-router";
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
