{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.cliproxy.rewind;
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
  };

  config = lib.mkIf (config.services.cliproxy.enable && cfg.enable) {
    systemd.services.cliproxy = {
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
