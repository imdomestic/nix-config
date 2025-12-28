{
  config,
  pkgs,
  ...
}: let
  gateConfig = pkgs.writeText "gate.yml" ''
    config:
      bind: 0.0.0.0:25566
      onlineMode: false

      servers:
        ftb: 10.0.0.66:25571

      try:
        - ftb

      forwarding:
        mode: legacy

      status:
        motd: |
          §bGate -> CatServer
          §e10.0.0.66:25571
        showMaxPlayers: 10000
        logPingRequests: false
  '';
  # lite:
  #   enabled: true
  #   routes:
  #     - host: "*"
  #       backend: 10.0.0.66:25565
in {
  virtualisation.podman.enable = true;
  virtualisation.oci-containers.backend = "podman";

  virtualisation.oci-containers.containers.gate = {
    image = "ghcr.io/minekube/gate:latest";
    autoStart = true;

    extraOptions = ["--network=host"];

    volumes = [
      "${gateConfig}:/config.yml:ro"
    ];

    cmd = ["-c" "/config.yml"];
  };

  networking.firewall.allowedTCPPorts = [25566];
}
