# 运营网络：Velocity（带路由插件）+ 常驻大厅 + bingo Fleet。
#
# 大厅是常驻的 StatefulSet，世界存在 PVC 里，作为静态后端写在 velocity.toml。小游戏房间
# 是 Agones Fleet，由 minecraft/agones-{paper,fabric} 上报状态，Velocity 上的
# minecraft/velocity-router 按 GameServer 动态注册。旧服的定义见
# nixos/modules/minecraft/wuxi.nix，存档在 tank 的 /data/srv/minecraft。
{lib, ...}: let
  tag = import ../../../minecraft/image-tag.nix;

  images = {
    # CI（.github/workflows/k8s.yml）构建，tag 是 minecraft/ 的内容哈希。
    server = "ghcr.io/imdomestic/mc-server:${tag}";
    proxy = "ghcr.io/imdomestic/mc-proxy:${tag}";
    seed = "busybox:1.37.0";
  };

  # k8s 默认往 Pod 里注入同命名空间每个 Service 的环境变量。Velocity 的 Service 叫 proxy，
  # 注入的 PROXY_PORT=tcp://... 会被 itzg 当成 HTTP 代理，启动时下载服务端就卡死。
  # 见 docs/incidents.md#mc-service-links-proxy。
  noServiceLinks.enableServiceLinks = false;

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

  # 旧服是离线模式，存档里的玩家数据按离线 UUID 存。测试期间保持一致，只在 tailnet 和局域网内可达。
  # 静态后端只有常驻大厅；小游戏房间由路由插件动态注册。
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

  # 所有后端共用的环境变量。
  commonEnv = {
    EULA = "TRUE";
    ONLINE_MODE = "FALSE";
    ENFORCE_SECURE_PROFILE = "FALSE";
    # 堆交给 JVM 按容器上限算，留出堆外内存。
    MEMORY = "";
    JVM_XX_OPTS = "-XX:MaxRAMPercentage=75";
    # 1.21.2 起服务器空 60 秒会暂停 tick，插件在 tick 里 ping，暂停就会被判 Unhealthy。
    # 见 docs/incidents.md#mc-pause-when-empty。老版本不认这个属性，会忽略。
    PAUSE_WHEN_EMPTY_SECONDS = "0";
  };

  # 一种后端对应一个 Fleet。数据放 emptyDir，每次启动从旧存档里拷 seedPaths 指定的内容，
  # 原存档只读挂载，不会被改。
  mkFleet = name: {
    labels,
    env,
    secretEnv,
    memory,
    seedPaths,
    # 从容器启动到插件开始 ping 的宽限期：要覆盖下载服务端和加载世界的时间。
    healthDelay,
    extraVolumes ? [],
    extraMounts ? [],
  }: {
    apiVersion = "agones.dev/v1";
    kind = "Fleet";
    metadata.name = name;
    # replicas 交给 FleetAutoscaler，这里不写，否则 Argo CD 会和它来回改。
    spec.template = {
      metadata.labels = {"mc.imdomestic.com/kind" = name;} // labels;
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
        # 插件开始后每秒 ping 一次，连续 60 秒没有才判 Unhealthy，扛得住 GC 和存盘的卡顿。
        health = {
          initialDelaySeconds = healthDelay;
          periodSeconds = 5;
          failureThreshold = 12;
        };
        lists.players.capacity = 100;
        template.spec =
          noServiceLinks
          // {
            initContainers = [
              {
                name = "seed";
                image = images.seed;
                command = [
                  "sh"
                  "-c"
                  ''
                    for p in ${lib.concatStringsSep " " seedPaths}; do
                      if [ -e "/seed/$p" ]; then
                        mkdir -p "/data/$(dirname "$p")"
                        cp -a "/seed/$p" "/data/$(dirname "$p")/"
                      fi
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
                image = images.server;
                env =
                  lib.mapAttrsToList (name: value: {inherit name value;}) (commonEnv // env)
                  ++ [
                    {
                      name = secretEnv;
                      valueFrom = forwardingSecret;
                    }
                  ];
                resources = {
                  requests.memory = memory;
                  limits.memory = memory;
                };
                volumeMounts =
                  [
                    {
                      name = "data";
                      mountPath = "/data";
                    }
                  ]
                  ++ extraMounts;
              }
            ];
            volumes =
              [
                {
                  name = "data";
                  emptyDir = {};
                }
                {
                  name = "seed";
                  hostPath = {
                    path = "/data/srv/minecraft/${name}";
                    type = "Directory";
                  };
                }
              ]
              ++ extraVolumes;
          };
      };
    };
  };

  # 始终留 bufferSize 台没人的待命：开房间就是从里面分配一台，缩容只会删 Ready 的。
  mkAutoscaler = name: {
    bufferSize,
    maxReplicas,
  }: {
    apiVersion = "autoscaling.agones.dev/v1";
    kind = "FleetAutoscaler";
    metadata.name = name;
    spec = {
      fleetName = name;
      policy = {
        type = "Buffer";
        buffer = {
          inherit bufferSize maxReplicas;
          minReplicas = bufferSize;
        };
      };
      sync = {
        type = "FixedInterval";
        fixedInterval.seconds = 30;
      };
    };
  };

  # 管理数据（OP、白名单、封禁）：房间从旧存档里只拷这些和自己的配置。
  adminFiles = ["ops.json" "whitelist.json" "banned-players.json" "banned-ips.json" "usercache.json"];

  # bingo 是 ROOM 模式：所有人离开 2 分钟后存盘、Shutdown，由 Fleet 换一台新的。
  # 世界不从旧存档拷，每台都是新生成的；只拷 bingo 的配置。mod 只装在服务端，原版客户端能进。
  bingo = mkFleet "bingo" {
    labels = {
      "mc.imdomestic.com/protocol" = "774"; # 1.21.11
      "mc.imdomestic.com/soft-cap" = "16";
    };
    env = {
      TYPE = "FABRIC";
      VERSION = "1.21.11";
      FABRIC_LOADER_VERSION = "0.19.5";
      MOTD = "bingo 1.21.11";
      MODS = lib.concatStringsSep "," [
        "https://cdn.modrinth.com/data/P7dR8mSH/versions/DdVHbeR1/fabric-api-0.141.1%2B1.21.11.jar"
        "https://cdn.modrinth.com/data/8dI2tmqs/versions/nR8AIdvx/FabricProxy-Lite-2.11.0.jar"
        "https://cdn.modrinth.com/data/gvQqBUqZ/versions/gl30uZvp/lithium-fabric-0.21.2%2Bmc1.21.11.jar"
        "https://cdn.modrinth.com/data/mHeNceaH/versions/Vb6yPYhc/bingo-2.9.7%2Bmc1.21.11.jar"
      ];
      MC_AGONES_MODE = "room";
      MC_AGONES_IDLE_SECONDS = "120";
    };
    # FabricProxy-Lite 读这个环境变量；旧存档里的 FabricProxy-Lite.toml 带着旧密钥，所以不拷。
    secretEnv = "FABRIC_PROXY_SECRET";
    memory = "4Gi";
    seedPaths = ["config/yet-another-minecraft-bingo"] ++ adminFiles;
    # Fabric 要先装 loader、下载原版服务端和 mod，再生成新世界，比大厅慢得多。
    healthDelay = 300;
  };
in {
  applications.mc = {
    namespace = "mc";
    # 命名空间和 velocity-forwarding 密钥一起由 nixos/hosts/tank/k3s.nix 建。
    createNamespace = false;

    # Fleet 和 FleetAutoscaler 没有 nixidy 的类型定义，原样放进去。
    yamls = map builtins.toJSON [
      bingo
      # 待命两台：bingo 冷启动约 5 分钟，前后脚开两个房间时第二个人不用等。
      (mkAutoscaler "bingo" {
        bufferSize = 2;
        maxReplicas = 6;
      })
    ];

    resources = {
      # 常驻大厅：PVC 第一次挂上时从旧存档整份拷一次，之后世界一直保留。
      # 不在 Agones 下运行，镜像里的插件什么都不做。
      statefulSets.lobby.spec = {
        serviceName = "lobby";
        replicas = 1;
        selector.matchLabels.app = "lobby";
        template = {
          metadata.labels.app = "lobby";
          spec =
            noServiceLinks
            // {
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
                  lib.mapAttrs (_: value: {inherit value;}) (commonEnv
                    // {
                      TYPE = "PAPER";
                      VERSION = "1.21.1";
                      PAPER_BUILD = "133";
                      MOTD = "lobby";
                      ALLOW_NETHER = "FALSE";
                      SPAWN_PROTECTION = "999";
                      MODE = "adventure";
                    })
                  // {CFG_FORWARDING_SECRET.valueFrom = forwardingSecret;};
                ports.minecraft.containerPort = 25565;
                volumeMounts = {
                  "/data".name = "data";
                  "/config".name = "config";
                };
                resources = {
                  requests.memory = "3Gi";
                  limits.memory = "3Gi";
                };
                readinessProbe = {
                  exec.command = ["mc-health"];
                  initialDelaySeconds = 30;
                  periodSeconds = 10;
                };
              };
              volumes = {
                config.configMap.name = "lobby-config";
                seed.hostPath = {
                  path = "/data/srv/minecraft/lobby";
                  type = "Directory";
                };
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
      services.lobby.spec = {
        selector.app = "lobby";
        ports.minecraft = {
          port = 25565;
          targetPort = 25565;
        };
      };

      configMaps.lobby-config.data."paper-global.yml" = paperGlobal;
      configMaps.velocity.data."velocity.toml" = velocityToml;

      # 路由插件：监听 GameServer、开房间（创建 GameServerAllocation）、房主关房（删 GameServer）。
      # 对局阶段的标签（agones.dev/sdk-phase）由房间自己通过 SDK 写，插件不改 GameServer。
      serviceAccounts.velocity-router = {};
      roles.velocity-router.rules = [
        {
          apiGroups = ["agones.dev"];
          resources = ["gameservers"];
          verbs = ["get" "list" "watch" "delete"];
        }
        {
          apiGroups = ["allocation.agones.dev"];
          resources = ["gameserverallocations"];
          verbs = ["create"];
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
          spec =
            noServiceLinks
            // {
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
                  # 静态后端的协议版本，和大厅的 VERSION（1.21.1）对应；动态后端靠 GameServer 标签。
                  # 见 docs/incidents.md#mc-via-static-protocol。
                  ROUTER_STATIC_PROTOCOLS.value = "lobby=767";
                };
                ports.minecraft.containerPort = 25565;
                # Velocity 启动完才监听端口，滚动更新时等它能接人再停旧的。
                readinessProbe = {
                  tcpSocket.port = 25565;
                  periodSeconds = 5;
                };
                # 路由插件的只读状态接口（GET /v1/status），给 QQ bot 查在线和房间。
                ports.status.containerPort = 8080;
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

      # k3s 自带的 servicelb 会在 tank 上占住 25565 和 25580，tailnet 和局域网都能连。
      # 状态接口不带私有房间的房间码，所以和游戏端口一样不设认证。
      services.proxy.spec = {
        type = "LoadBalancer";
        selector.app = "proxy";
        ports.minecraft = {
          port = 25565;
          targetPort = 25565;
        };
        ports.status = {
          port = 25580;
          targetPort = 8080;
        };
      };
    };
  };
}
