{
  config,
  lib,
  ...
}: let
  bonsai = import ../../lib/bonsai-models.nix;
in {
  sops.secrets."bonsai/api_key" = {
    sopsFile = ../../secrets/clients/bonsai.yaml;
    restartUnits = ["llama-swap.service"];
  };
  sops.templates."bonsai-environment".content = ''
    BONSAI_API_KEY=${config.sops.placeholder."bonsai/api_key"}
  '';

  services.llama-swap = {
    listenAddress = lib.mkForce "0.0.0.0";
    settings.apiKeys = ["\${env.BONSAI_API_KEY}"];
  };
  systemd.services.llama-swap.serviceConfig.EnvironmentFile =
    config.sops.templates."bonsai-environment".path;

  my.tailscale.guardedTCPServices.llama-swap = [bonsai.port];
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [bonsai.port];
  networking.nftables.tables.bonsai-client = {
    family = "inet";
    content = ''
      chain input {
        type filter hook input priority -11; policy accept;
        iifname "tailscale0" meta nfproto ipv4 ip saddr != 100.64.0.25 tcp dport ${toString bonsai.port} counter drop
        iifname "tailscale0" meta nfproto ipv6 tcp dport ${toString bonsai.port} counter drop
      }
    '';
  };
}
