{
  hosts.r5s = {
    system = "aarch64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["server" "router"];
    tsName = "r5s.inner.imdomestic.com";
    ageKey = "age1weu2ymkv0pa79n3f5rcxj90dya57lktk42q2kwl5ytug646dgfdqpgrzw5";
    # tank 那一段;tank 的救援 initrd 也在这段上(192.168.20.50)。
    lanRoutes = ["192.168.20.0/24"];
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "xray.service" "mihomo.service" "ddns-go.service" "systemd-resolved.service"];
    };
    ip = "10.0.0.9";
    sshUser = "root";
    maxTier = "interactive";
    buildOn = "r6s";

    users = {
      nix = {};
      hank = {};
    };
  };
}
