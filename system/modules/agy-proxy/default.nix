{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.agy-proxy;
  login = pkgs.writeShellScript "agy-proxy-login-worker" ''
    exec ${lib.getExe cfg.package} login \
      --credential-file ${lib.escapeShellArg cfg.credentialsFile} \
      --oauth-client-file "$CREDENTIALS_DIRECTORY/oauth-client" "$@"
  '';
  args =
    [
      (lib.getExe cfg.package)
      "--listen"
      "127.0.0.1:${toString cfg.port}"
      "--client-key-file"
      "%d/client-key"
      "--credential-file"
      cfg.credentialsFile
      "--oauth-client-file"
      "%d/oauth-client"
    ]
    ++ lib.optional cfg.refreshCredentials "--refresh-credentials"
    ++ lib.optionals (cfg.userAgent != null) ["--user-agent" cfg.userAgent];
in {
  options.services.agy-proxy = {
    enable = lib.mkEnableOption "the independent Antigravity Gemini gateway";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../../../pkgs/agy-proxy {};
      description = "agy-proxy package, including the interactive OAuth login command.";
    };
    port = lib.mkOption {
      type = lib.types.port;
      default = 8319;
      description = "Loopback-only HTTP port; expose Gemini through an authenticated TLS frontend.";
    };
    clientKeyFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime client API key file, loaded privately by systemd; never a Nix store path.";
    };
    oauthClientFile = lib.mkOption {
      type = lib.types.str;
      description = "Private runtime JSON containing installed-app client_id and client_secret.";
    };
    credentialsFile = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/agy-proxy/oauth.json";
      readOnly = true;
      description = "Private runtime OAuth state owned and refreshed only by agy-proxy.";
    };
    refreshCredentials = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Refresh and atomically persist this service's own OAuth file before expiry.";
    };
    userAgent = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Explicit protocol profile override; null uses the package's observed CLI profile.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (path: lib.hasPrefix "/" path && !lib.hasPrefix "/nix/store/" path) [cfg.clientKeyFile cfg.oauthClientFile];
        message = "agy-proxy client key and OAuth client configuration must be absolute runtime secret paths, not store paths.";
      }
    ];

    users.users.agy-proxy = {
      isSystemUser = true;
      group = "agy-proxy";
    };
    users.groups.agy-proxy = {};

    systemd.services.agy-proxy = {
      description = "Independent Antigravity Gemini gateway";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      wants = ["network-online.target"];
      environment.SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
      serviceConfig = {
        User = "agy-proxy";
        Group = "agy-proxy";
        StateDirectory = "agy-proxy";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/agy-proxy";
        LoadCredential = ["client-key:${cfg.clientKeyFile}" "oauth-client:${cfg.oauthClientFile}"];
        ExecStart = lib.escapeShellArgs args;
        Restart = "on-failure";
        RestartSec = "5s";
        UMask = "0077";
        MemoryHigh = "384M";
        MemoryMax = "512M";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = [];
        SystemCallArchitectures = "native";
      };
    };

    environment.systemPackages = [
      cfg.package
      (pkgs.writeShellScriptBin "agy-proxy-login" ''
        set -euo pipefail
        if [ "$(${pkgs.coreutils}/bin/id -u)" != 0 ]; then
          exec sudo -- "$0" "$@"
        fi
        # Match the service's credential ACLs without opening SOPS parent directories.
        exec ${pkgs.systemd}/bin/systemd-run --quiet --pipe --wait --collect \
          --unit=agy-proxy-login \
          --property=User=agy-proxy --property=Group=agy-proxy \
          --property=WorkingDirectory=/var/lib/agy-proxy \
          --property=UMask=0077 --property=RuntimeMaxSec=10min \
          --property=LoadCredential=oauth-client:${lib.escapeShellArg cfg.oauthClientFile} \
          ${login} "$@"
      '')
    ];
  };
}
