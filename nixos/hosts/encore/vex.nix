{
  inputs,
  pkgs,
  ...
}: let
  fabric = {
    enabled = true;
    gradle_task = "build";
    artifact_glob = "build/libs/*.jar";
    artifact_exclude = ["*-sources.jar" "*-dev*.jar" "*-javadoc.jar"];
    loader_version_property = "fabric_loader_version";
    agent = "fabric-26-3";
    deps = [
      {
        name = "fabric-api";
        url = "https://maven.fabricmc.net/net/fabricmc/fabric-api/fabric-api/\${fabric_version}/fabric-api-\${fabric_version}.jar";
        side = "both";
      }
    ];
  };
  project = {
    default_branch = "main";
    trust = "trusted";
    minecraft = {
      version = "26.3";
      java = 25;
    };
    build.source = "host";
    members = {
      linwhite = "owner";
      hank = "viewer";
    };
    loaders.fabric = fabric;
    quota = {
      max_rooms = 6;
      room_memory_max = "5Gi";
      build_cache = 20;
      snapshot_keep = 5;
      snapshot_keep_days = 14;
    };
  };
in {
  imports = [inputs.vex.nixosModules.vexd];
  systemd.tmpfiles.rules = [
    "z /var/lib/vex/kubeconfig 0640 root vexd -"
    "z /var/lib/vex/secrets/signing.key 0640 root vexd -"
    "d /var/lib/vex/agents 0755 root root -"
  ];
  services.vexd = {
    enable = true;
    adminUsers = ["linwhite"];
    executable = "/nix/var/nix/profiles/vex/bin/vexd";
    dns = {
      enable = true;
      listenAddresses = ["100.64.0.43" "10.1.2.137"];
      answerAddress = "100.64.0.43";
    };
    firewallInterfaces = ["tailscale0" "wlo1"];
    settings = {
      server = {
        name = "encore";
        listen = ["100.64.0.43:8790" "10.1.2.137:8790"];
        public_base_url = "http://encore.inner.imdomestic.com:8790";
        internal_base_url = "http://10.1.2.137:8790";
        data_dir = "/srv/vex";
        zone = "vex.internal";
        router_address = "10.1.2.137:25565";
      };
      minecraft.accept_eula = true;
      runtime = {
        backend = "kubernetes";
        kubernetes = {
          kubeconfig_file = "/var/lib/vex/kubeconfig";
          storage_class = "local-path";
          webhook_sources = ["10.42.0.0/16"];
          nodes = {
            encore = {
              k8s_name = "encore";
              roles = ["persistent" "ephemeral" "build"];
              priority = 10;
              max_rooms = 2;
            };
            seraph = {
              k8s_name = "seraph";
              roles = ["ephemeral"];
              priority = 20;
              max_rooms = 4;
            };
          };
        };
      };
      runtimes.java25 = {
        server_image = "itzg/minecraft-server:java25@sha256:7462fe34a56686719463ff898a674c1a1ce802988138d2bfdeff2507fb1644e8";
        jdk_home = pkgs.jdk25.home;
      };
      agents.fabric-26-3 = {
        minecraft = "26.3";
        loader = "fabric";
        version = "1.0.0";
        file = "/var/lib/vex/agents/vex-agent-26.3-1.0.0.jar";
      };
      archive = {
        backend = "rsync-ssh";
        rsync_ssh = {
          target = "vex-archive@tank.inner.imdomestic.com:/srv/archive/vex";
          identity_file = "/var/lib/vex/ssh/id_ed25519";
          known_hosts_file = "/var/lib/vex/ssh/known_hosts";
          bwlimit = "5M";
        };
      };
      auth = {
        signing_key_file = "/var/lib/vex/secrets/signing.key";
        session_ttl = "2160h";
        invite_ttl = "24h";
        admin_socket = "/run/vex/admin.sock";
      };
      users = {
        linwhite = {
          admin = true;
          identities = ["static:linwhite"];
          token_sha256 = "85b37fb278de246e1ace06b2e37344dc972dab721d3501e3f4cab2212043c9fa";
          minecraft = ["bba1056c-9564-4e86-b8e6-5fbdad19831d"];
        };
        hank = {
          identities = ["static:hank"];
          token_sha256 = "ed1e1046c453eb3ee657d7d06f2d21e5946da6b274699a96b0e8784bf3b6b0bb";
          minecraft = [];
        };
      };
      projects = {
        chorus =
          project
          // {
            remote = "https://github.com/imdomestic/chorus.git";
            loaders.fabric =
              fabric
              // {
                gradle_task = ":fabric:assemble";
                artifact_glob = "fabric/build/libs/*.jar";
              };
            worlds.extra_root_entries = ["chorus-checkpoint.json"];
          };
        example = project // {remote = "https://github.com/imdomestic/vex-example-fabric.git";};
      };
      build = {
        max_concurrent = 1;
        lock_file = "/var/lib/vex/build.lock";
      };
      rooms = {
        heap = "4G";
        join_lease = "3m";
        idle = {
          branch = "10m";
          commit = "10m";
          world = "10m";
        };
      };
      worlds.scanner_file = "/nix/var/nix/profiles/vex/bin/vex-world-scanner";
    };
  };
}
