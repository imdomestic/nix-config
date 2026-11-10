{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.cliproxy.rewind;
  balanceConfig = (pkgs.formats.json {}).generate "rewind-balance.json" {
    listen_address = cfg.balance.bindAddress;
    port = cfg.balance.port;
    client_key_file = cfg.balance.clientKeyFile;
    api_key_file = cfg.apiKeyFile;
    device_file = "/var/lib/cli-proxy-api/rewind/device.json";
  };
  auth = (pkgs.formats.json {}).generate "rewind-auth.json" {
    type = "rewind";
    prefix = "rewind";
    api_key_file = cfg.apiKeyFile;
    device_file = "/var/lib/cli-proxy-api/rewind/device.json";
  };
in {
  options.services.cliproxy.rewind = {
    enable = lib.mkEnableOption "the Rewind Responses provider plugin";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../../../pkgs/cliproxy-rewind {};
      description = "Rewind provider shared library for CLIProxyAPI.";
    };
    apiKeyFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime file containing the Rewind API key, readable by cliproxy.";
    };
    balance = {
      enable = lib.mkEnableOption "the authenticated, cached Rewind balance listener";
      bindAddress = lib.mkOption {
        type = lib.types.str;
        default = config.services.cliproxy.bindAddress;
        description = "Tailnet address or MagicDNS name for the read-only balance listener.";
      };
      port = lib.mkOption {
        type = lib.types.port;
        default = config.my.fleet.placements.rewind-balance.port;
        description = "Port of the Rewind balance listener.";
      };
      clientKeyFile = lib.mkOption {
        type = lib.types.str;
        default = config.sops.secrets."cliproxy/api_key".path;
        description = "Runtime file containing the gateway client key, never the management key.";
      };
    };
  };

  config = lib.mkIf (config.services.cliproxy.enable && cfg.enable) {
    assertions = [
      {
        assertion = lib.versionAtLeast (config.services.cliproxy.package.version or "0") "8.0.63";
        message = "Rewind requires CLIProxyAPI >= 8.0.63 for non-replayable stream_truncated errors.";
      }
      {
        assertion = !cfg.balance.enable || cfg.balance.port != config.services.cliproxy.port;
        message = "Rewind balance and model listeners must use different ports.";
      }
    ];
    networking.firewall.interfaces.tailscale0.allowedTCPPorts = lib.optional cfg.balance.enable cfg.balance.port;
    sops.secrets."cliproxy/api_key".owner = lib.mkIf cfg.balance.enable "cliproxy";
    systemd.services.cliproxy = {
      environment = lib.optionalAttrs cfg.balance.enable {
        CLIPROXY_REWIND_BALANCE_CONFIG = toString balanceConfig;
      };
      # With script activation, SOPS has already installed secrets before services start.
      after = lib.optional config.sops.useSystemdActivation "sops-install-secrets.service";
      wants = lib.optional config.sops.useSystemdActivation "sops-install-secrets.service";
      preStart = ''
        install -d -m700 /var/lib/cli-proxy-api/auths /var/lib/cli-proxy-api/rewind
        install -m600 ${auth} /var/lib/cli-proxy-api/auths/rewind.json
      '';
    };
  };
}
