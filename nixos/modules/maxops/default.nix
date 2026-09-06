{
  config,
  lib,
  inputs,
  ...
}: let
  host = config.my.host;
  cfg = host.maxops;
  localHub = host.name == "h610";
in {
  imports = [inputs.maxops.nixosModules.agent];

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = host.tsIp != null;
          message = "maxops requires an inventory Tailscale address";
        }
        {
          assertion = cfg.readableUnits != [];
          message = "maxops requires an explicit service allowlist";
        }
      ];
      sops.secrets."maxops/agent_token" =
        {
          mode = "0400";
          restartUnits = ["maxops-agent.service"] ++ lib.optional localHub "maxops-hub.service";
        }
        // lib.optionalAttrs (!localHub) {
          sopsFile = ../../../secrets/maxops + "/${host.name}.yaml";
          key = "agent_token";
        };
      services.maxops-agent = {
        enable = true;
        hostName = host.name;
        listenAddress =
          if localHub
          then "127.0.0.1"
          else host.tsIp;
        tokenFile = config.sops.secrets."maxops/agent_token".path;
        readableUnits = cfg.readableUnits;
        allowLogs = true;
      };
      networking.firewall.interfaces.tailscale0.allowedTCPPorts = lib.optional (!localHub) config.services.maxops-agent.port;
    })
  ];
}
