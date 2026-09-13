{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.tailscale;
  check = pkgs.writeShellScript "tailscale-bind-ready" ''
    export TAILSCALE_BIND_IP=${pkgs.iproute2}/bin/ip
    exec ${pkgs.coreutils}/bin/timeout 125 ${pkgs.python3}/bin/python3 \
      ${./resolve-bind.py} check ${lib.escapeShellArg config.my.host.tsName}
  '';
in {
  options.my.tailscale.bindServices = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [];
    description = "Services which resolve their own MagicDNS name before binding. Unit names without .service.";
  };
  config = lib.mkIf (cfg.bindServices != []) {
    assertions = [
      {
        assertion = cfg.enable && config.my.host.tsName != null;
        message = "Tailscale listeners require an enabled client and my.host.tsName.";
      }
    ];
    systemd.services = lib.genAttrs cfg.bindServices (_: {
      after = ["tailscaled.service" "tailscaled-set.service"];
      wants = ["tailscaled.service" "tailscaled-set.service"];
      serviceConfig = {
        ExecStartPre = lib.mkBefore [check];
        RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK"];
      };
    });
  };
}
