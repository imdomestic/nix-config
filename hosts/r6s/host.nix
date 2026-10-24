{
  hosts.r6s = {
    system = "aarch64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["server" "router"];
    tsName = "r6s.inner.imdomestic.com";
    ageKey = "age1spxgjvmk89lxzu56nrssy3hsgkzkc79w9pkncesxdjmugk2t9vus56esfj";
    lanRoutes = ["192.168.22.0/24"];
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "xray.service" "mihomo.service" "ddns-go.service" "systemd-resolved.service"];
    };
    ip = "10.0.0.4";
    sshUser = "root";
    maxTier = "interactive";

    modules = [
      ./system.nix
      ./hardware-configuration.nix
    ];

    externalModules = [
      # inputs.determinate.nixosModule.default
    ];

    users.hank = {};
  };
}
