{
  config,
  pkgs,
  ...
}: let
  gateConfig = pkgs.writeText "gate.yml" ''
    config:
      bind: 0.0.0.0:25565
      onlineMode: false

      bedrock:
        managed: true

      lite:
        enabled: true
        routes:
          - host: "sh.imdomestic.com"
            backend: 10.0.0.66:25565
            proxyProtocol: true
            tcpShieldRealIP: false
  '';
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
