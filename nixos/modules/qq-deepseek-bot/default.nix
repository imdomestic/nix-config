{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.qq-deepseek-bot;
  serviceName = "qq-deepseek-bot";
  statePath = "/var/lib/${serviceName}";
  cachePath = "/var/cache/${serviceName}";
  setup = pkgs.writeShellApplication {
    name = "${serviceName}-setup";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.uv
    ];
    text = ''
      export HOME=${lib.escapeShellArg statePath}
      export UV_CACHE_DIR=${lib.escapeShellArg "${cachePath}/uv"}
      export UV_LINK_MODE=copy
      export UV_NO_MANAGED_PYTHON=1
      export UV_NO_PROGRESS=1
      export UV_PROJECT_ENVIRONMENT=${lib.escapeShellArg "${statePath}/venv"}

      legacy_state=${lib.escapeShellArg "${cfg.sourceDirectory}/src/plugins/ai_chat/assets"}
      state_dir=${lib.escapeShellArg "${statePath}/state"}
      mkdir -p "$UV_CACHE_DIR" "$state_dir"

      for state_file in learned_stickers.json model_preferences.json user_profiles.json warmup_state.json; do
        if [[ -f "$legacy_state/$state_file" && ! -e "$state_dir/$state_file" ]]; then
          install -m 600 "$legacy_state/$state_file" "$state_dir/$state_file"
        fi
      done

      uv sync \
        --project ${lib.escapeShellArg cfg.sourceDirectory} \
        --frozen \
        --no-install-project \
        --python ${lib.escapeShellArg "${pkgs.python312}/bin/python"}
    '';
  };
  start = pkgs.writeShellScript "${serviceName}-start" ''
    export HOME=${lib.escapeShellArg statePath}
    export AI_STATE_DIR=${lib.escapeShellArg "${statePath}/state"}
    export AI_CACHE_DIR=${lib.escapeShellArg cachePath}
    export AI_SANDBOX_ENABLED=${
      if cfg.sandbox.enable
      then "true"
      else "false"
    }
    export HOST=${lib.escapeShellArg cfg.host}
    export PORT=${toString cfg.port}
    export PYTHONUNBUFFERED=1

    cd ${lib.escapeShellArg cfg.sourceDirectory}
    exec ${lib.escapeShellArg "${statePath}/venv/bin/python"} bot.py
  '';
in {
  options.services.qq-deepseek-bot = {
    enable = lib.mkEnableOption "the DeepSeek-powered QQ bot";

    sourceDirectory = lib.mkOption {
      type = lib.types.str;
      example = "/srv/qq-deepseek-bot";
      description = "Bot source directory containing bot.py, pyproject.toml, and uv.lock.";
    };

    environmentFile = lib.mkOption {
      type = lib.types.str;
      example = "/run/secrets/qq-deepseek-bot.env";
      description = "Environment file containing the bot's API keys and runtime settings.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = serviceName;
      description = "User account that runs the bot.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = serviceName;
      description = "Primary group of the bot process.";
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Address used by the OneBot reverse WebSocket server.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Port used by the OneBot reverse WebSocket server.";
    };

    sandbox.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Allow the bot to create Docker-backed execution sandboxes.";
    };

    napcat = {
      enable = lib.mkEnableOption "a dedicated NapCat container for this bot";

      account = lib.mkOption {
        type = lib.types.str;
        example = "123456789";
        description = "QQ account logged in by the dedicated NapCat container.";
      };

      image = lib.mkOption {
        type = lib.types.str;
        default = "mlikiowa/napcat-docker:latest";
        description = "NapCat container image.";
      };

      reverseWebsocketUrl = lib.mkOption {
        type = lib.types.str;
        default = "ws://host.docker.internal:${toString cfg.port}/onebot/v11/ws";
        description = "OneBot reverse WebSocket URL used by NapCat.";
      };

      webuiAddress = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1";
        description = "Host address used for the NapCat WebUI port mapping.";
      };

      webuiPort = lib.mkOption {
        type = lib.types.port;
        default = 6100;
        description = "Host port used for the dedicated NapCat WebUI.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${serviceName} = lib.mkIf (cfg.group == serviceName) {};
    users.users.${serviceName} = lib.mkIf (cfg.user == serviceName) {
      isSystemUser = true;
      group = cfg.group;
      home = statePath;
    };

    systemd.services.${serviceName} = {
      description = "DeepSeek QQ bot";
      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      after = ["network-online.target"];
      path = lib.optionals cfg.sandbox.enable [pkgs.docker];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        SupplementaryGroups = lib.optional cfg.sandbox.enable "docker";
        StateDirectory = serviceName;
        CacheDirectory = serviceName;
        WorkingDirectory = cfg.sourceDirectory;
        EnvironmentFile = cfg.environmentFile;
        ExecStartPre = "${setup}/bin/${serviceName}-setup";
        ExecStart = start;
        Restart = "on-failure";
        RestartSec = 5;
        UMask = "0077";

        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectHome = "read-only";
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictSUIDSGID = true;
      };
    };

    virtualisation = lib.mkIf cfg.napcat.enable {
      docker.enable = true;
      oci-containers = {
        backend = "docker";
        containers.napcat-chat-bot = {
          image = cfg.napcat.image;
          autoStart = true;
          environment = {
            ACCOUNT = cfg.napcat.account;
            WSR_ENABLE = "true";
            WS_URLS = builtins.toJSON [cfg.napcat.reverseWebsocketUrl];
          };
          ports = [
            "${cfg.napcat.webuiAddress}:${toString cfg.napcat.webuiPort}:6099"
          ];
          volumes = [
            "/var/lib/napcat-chat-bot/QQ:/app/.config/QQ"
            "/var/lib/napcat-chat-bot/config:/app/napcat/config"
            "/var/lib/napcat-chat-bot/outbox:/data/outbox"
          ];
          extraOptions = [
            "--add-host=host.docker.internal:host-gateway"
          ];
        };
      };
    };

    systemd.services.docker-napcat-chat-bot = lib.mkIf cfg.napcat.enable {
      wants = ["${serviceName}.service"];
      after = ["${serviceName}.service"];
    };

    systemd.tmpfiles.rules = lib.optionals cfg.napcat.enable [
      "d /var/lib/napcat-chat-bot 0700 root root -"
      "d /var/lib/napcat-chat-bot/QQ 0700 root root -"
      "d /var/lib/napcat-chat-bot/config 0700 root root -"
      "d /var/lib/napcat-chat-bot/outbox 0700 root root -"
    ];
  };
}
