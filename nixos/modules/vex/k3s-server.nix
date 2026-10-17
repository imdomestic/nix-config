{config, ...}: {
  assertions = [
    {
      assertion = config.networking.hostName == "encore";
      message = "Vex k3s server requires encore";
    }
    {
      assertion = config.networking.nftables.enable;
      message = "Vex k3s requires the nftables firewall";
    }
    {
      assertion = config.services.k3s.package.version == "1.35.7+k3s1";
      message = "Vex requires k3s 1.35.7+k3s1";
    }
  ];

  services.k3s = {
    enable = true;
    role = "server";
    nodeName = "encore";
    nodeIP = "10.1.2.137";
    nodeLabel = ["svccontroller.k3s.cattle.io/enablelb=true"];
    disable = ["traefik"];
    extraFlags = [
      "--bind-address=10.1.2.137"
      "--advertise-address=10.1.2.137"
      "--flannel-iface=wlo1"
      "--write-kubeconfig-mode=0600"
      "--kube-proxy-arg=nodeport-addresses=10.1.2.137/32"
    ];
  };

  boot.kernelModules = ["br_netfilter" "overlay"];
  boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
  networking.firewall.extraInputRules = ''
    iifname "wlo1" ip saddr 10.1.2.0/24 tcp dport { 6443, 10250 } accept
    iifname "wlo1" ip saddr 10.1.2.0/24 udp dport 8472 accept
    iifname { "cni0", "flannel.1" } ip saddr 10.42.0.0/16 accept
  '';
  systemd.services.k3s = {
    environment.TMPDIR = "/var/cache/vex-k3s";
    serviceConfig = {
      CacheDirectory = "vex-k3s";
      CacheDirectoryMode = "0700";
    };
  };
}
