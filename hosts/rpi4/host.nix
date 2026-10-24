{inputs, ...}: {
  hosts.rpi4 = {
    system = "aarch64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["server" "router"];
    tsName = "rpi4.inner.imdomestic.com";
    ageKey = "age1lghdzjwhlwssu44ptp5853e48fy0pcxrxlpf4r7ruphplxna4vzqq6e2kh";
    # 悉尼公寓。原来是 192.168.20.0/24,和 r5s 撞车,2026-09-13 改到 2 段。
    lanRoutes = ["192.168.2.0/24"];
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "xray.service" "mihomo.service" "ddns-go.service" "systemd-resolved.service"];
    };
    ip = "10.0.0.6";
    sshUser = "root";
    maxTier = "interactive";
    buildOn = "r6s";

    externalModules = [
      inputs.nixos-hardware.nixosModules.raspberry-pi-4
    ];

    users.hank = {};
  };
}
