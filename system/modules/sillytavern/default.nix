{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.sillytavern;
  cliArguments = lib.filterAttrs (_: value: value != null) {
    inherit (cfg) port listenAddressIPv4 listenAddressIPv6;
    listen =
      if cfg.listen == null
      then null
      else lib.boolToString cfg.listen;
    whitelist =
      if cfg.whitelist == null
      then null
      else lib.boolToString cfg.whitelist;
  };
  placements = config.my.fleet.placements;
  placement = placements.sillytavern;
  domain = config.my.host.tsName;
  loginUser = lib.head config.my.host.usernames;
  bonsai = import ../../../lib/bonsai-models.nix;
  cliproxy = import ../../../lib/cliproxy-models.nix {placement = placements.cliproxy;};
  endpoint = service: "http://${service.tsName}:${toString service.port}/v1";
  credentialsDirectory = "/run/credentials/sillytavern-bootstrap.service";
  modelProxyPort = 8002;
  modelProxy = "http://127.0.0.1:${toString modelProxyPort}";
  cloud = {
    url = "${modelProxy}/cliproxy/v1";
    context = 131072;
    maxTokens = 4096;
  };
  localBonsai = {
    url = "${modelProxy}/bonsai/v1";
    inherit (bonsai) context;
    maxTokens = 4096;
  };
  localQwen = {
    url = endpoint placements.qwen-ninfer;
    context = 262144;
    maxTokens = 4096;
  };
  localOllama = {
    url = endpoint placements.ollama;
    context = 4096;
    maxTokens = 1024;
  };
  manifest = pkgs.writeText "sillytavern-bootstrap.json" (builtins.toJSON {
    endpoint = "http://127.0.0.1:${toString cfg.port}";
    username = loginUser;
    passwordFile = "${credentialsDirectory}/password";
    credentials = {};
    defaultProfile = "fleet-bonsai-hikari";
    profiles = [
      (localBonsai
        // {
          id = "fleet-bonsai-hikari";
          name = "Bonsai Hikari · seraph 本机";
          model = "bonsai-hikari";
          reasoningEffort = bonsai.models.bonsai-hikari.reasoningEffort;
        })
      (localBonsai
        // {
          id = "fleet-bonsai-main";
          name = "Bonsai 2 · seraph 本机";
          model = "bonsai-main";
          reasoningEffort = bonsai.models.bonsai-main.reasoningEffort;
        })
      (localQwen
        // {
          id = "fleet-qwen-swift";
          name = "Qwen3.8 27B Swift · taipan";
          model = "qwen3.8-27b";
        })
      (localQwen
        // {
          id = "fleet-qwen-aligned";
          name = "Qwen3.8 27B Aligned · taipan";
          model = "qwen3.8-27b-aligned";
        })
      (cloud
        // {
          id = "fleet-cliproxy";
          name = "CLIProxy · 全部模型";
          model = "gemini-3.8-flash-high";
        })
      (cloud
        // {
          id = "fleet-gpt";
          name = "CLIProxy · GPT 6.1 Sol";
          model = "gpt-6.1-sol";
          context = 262144;
          maxTokens = 8192;
          reasoningEffort = "low";
        })
      (cloud
        // {
          id = "fleet-claude";
          name = "CLIProxy · Claude Opus 4.6 Thinking";
          model = "claude-opus-4-6-thinking";
        })
      (cloud
        // {
          id = "fleet-vertex";
          name = "CLIProxy · Vertex Gemini 4 Argon";
          model = "vertex/gemini-4-argon";
          maxTokens = 8192;
        })
      (cloud
        // {
          id = "fleet-deepseek";
          name = "CLIProxy · DeepSeek V4.1 Flash";
          model = "opencode/deepseek-v4.1-flash";
          reasoningEffort = "low";
        })
      {
        id = "fleet-small-qwen";
        name = "Qwen3.5 4B · h610";
        url = endpoint placements.small-qwen;
        model = "qwen3.5-4b-q4_k_m";
        context = 32768;
        maxTokens = 2048;
      }
      (localOllama
        // {
          id = "fleet-ollama-qwen";
          name = "Ollama · Qwen3 8B · tank";
          model = "qwen3:8b";
        })
      (localOllama
        // {
          id = "fleet-ollama-gemma";
          name = "Ollama · Gemma 4 E4B · tank";
          model = "gemma4:e4b-it-q4_K_M";
        })
    ];
  });
in {
  assertions = [
    {
      assertion = config.services.tailscale.enable && domain != null && placement.host == config.my.host.name;
      message = "SillyTavern must run on its registered Tailnet host.";
    }
    {
      assertion = cfg.package.version == "1.18.0";
      message = "Validate SillyTavern's bootstrap REST schemas before upgrading from 1.18.0.";
    }
  ];

  sops.secrets = {
    "sillytavern/password" = {};
    "cliproxy/api_key" = {
      sopsFile = ../../../secrets/clients/cliproxy.yaml;
      restartUnits = ["nginx.service"];
    };
    "bonsai/api_key".restartUnits = ["nginx.service"];
  };
  # Bind real credentials to upstreams, not mutable browser profiles; see docs/sillytavern.md.
  sops.templates."sillytavern-cliproxy-header" = {
    owner = config.services.nginx.user;
    restartUnits = ["nginx.service"];
    content = ''
      proxy_set_header Authorization "Bearer ${config.sops.placeholder."cliproxy/api_key"}";
    '';
  };
  sops.templates."sillytavern-bonsai-header" = {
    owner = config.services.nginx.user;
    restartUnits = ["nginx.service"];
    content = ''
      proxy_set_header Authorization "Bearer ${config.sops.placeholder."bonsai/api_key"}";
    '';
  };
  # The native module has no settings option; only its missing settings go here.
  sops.templates."sillytavern-config" = {
    owner = cfg.user;
    restartUnits = ["sillytavern.service"];
    content = builtins.toJSON {
      basicAuthMode = true;
      basicAuthUser = {
        username = loginUser;
        password = config.sops.placeholder."sillytavern/password";
      };
      browserLaunch.enabled = false;
      enableForwardedWhitelist = false;
      whitelistDockerHosts = false;
      hostWhitelist = {
        enabled = true;
        hosts = [domain config.my.host.name];
      };
      privateAddressWhitelist = {
        enabled = true;
        allowedRanges = ["127.0.0.0/8" "::1/128" "100.64.0.0/10" "fd7a:115c:a1e0::/48"];
      };
      logging.minLogLevel = 1;
      openai.excludedModelPrefixes = ["rewind/"];
    };
  };

  services.sillytavern = {
    enable = true;
    # Keep conditional-use providers out of discovery and hand-entered generation.
    package = pkgs.sillytavern.overrideAttrs (old: {
      patches = (old.patches or []) ++ [./exclude-conditional-models.patch];
    });
    port = 8001;
    listen = true;
    listenAddressIPv4 = "127.0.0.1";
    listenAddressIPv6 = "::1";
    whitelist = true;
    configFile = "/var/lib/SillyTavern/server-config.yaml";
  };
  systemd.services.sillytavern = {
    # SillyTavern adds missing defaults at startup, so its fragment must be writable.
    preStart = ''
      ${pkgs.coreutils}/bin/install -m 0600 ${config.sops.templates."sillytavern-config".path} ${cfg.configFile}
    '';
    serviceConfig = {
      # Native "--listen=1" disables auth in yargs; docs/incidents.md#sillytavern-native-flags.
      ExecStart = lib.mkForce (lib.escapeShellArgs ([(lib.getExe cfg.package)] ++ lib.cli.toCommandLineGNU {} cliArguments));
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
  };
  systemd.services.sillytavern-bootstrap = {
    description = "Provision SillyTavern fleet model connections without exposing API keys";
    wantedBy = ["multi-user.target"];
    requires = ["sillytavern.service"];
    after = ["sillytavern.service"];
    partOf = ["sillytavern.service"];
    script = ''
      exec ${pkgs.python3}/bin/python3 ${./bootstrap.py} ${manifest}
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      TimeoutStartSec = 180;
      User = cfg.user;
      Group = cfg.group;
      LoadCredential = ["password:${config.sops.secrets."sillytavern/password".path}"];
      UMask = "0077";
      NoNewPrivileges = true;
      CapabilityBoundingSet = "";
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
      IPAddressDeny = "any";
      IPAddressAllow = "localhost";
    };
  };

  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    clientMaxBodySize = "100m";
    virtualHosts = {
      ${domain} = {
        serverAliases = [config.my.host.name];
        listen = [
          {
            addr = domain;
            inherit (placement) port;
          }
        ];
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
          extraConfig = ''
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            gzip off;
          '';
        };
      };
      sillytavern-models = {
        listen = [
          {
            addr = "127.0.0.1";
            port = modelProxyPort;
          }
        ];
        locations = {
          "/".return = "404";
          "^~ /cliproxy/v1/" = {
            proxyPass = "${cliproxy.baseUrl}/";
            extraConfig = ''
              include ${config.sops.templates."sillytavern-cliproxy-header".path};
              proxy_buffering off;
              proxy_request_buffering off;
              proxy_read_timeout 3600s;
              proxy_send_timeout 3600s;
              gzip off;
            '';
          };
          "^~ /bonsai/v1/" = {
            proxyPass = "http://${placements.bonsai-ninfer.tsName}:${toString bonsai.port}/v1/";
            extraConfig = ''
              include ${config.sops.templates."sillytavern-bonsai-header".path};
              proxy_buffering off;
              proxy_request_buffering off;
              proxy_read_timeout 3600s;
              proxy_send_timeout 3600s;
              gzip off;
            '';
          };
        };
      };
    };
  };
  my.tailscale = {
    bindServices = ["nginx"];
    guardedTCPServices.nginx = [placement.port];
  };
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [placement.port];
}
