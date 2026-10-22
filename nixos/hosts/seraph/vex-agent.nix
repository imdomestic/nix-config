{config, ...}: {
  assertions = [
    {
      assertion = config.networking.hostName == "seraph";
      message = "Vex k3s agent requires seraph";
    }
    {
      assertion = config.networking.nftables.enable;
      message = "Vex k3s requires the nftables firewall";
    }
    {
      assertion = config.services.k3s.package.version == "1.35.8+k3s1";
      message = "Vex requires k3s 1.35.8+k3s1";
    }
  ];

  sops.secrets."k3s/token" = {
    sopsFile = ../../../secrets/hosts/seraph.yaml;
    owner = "root";
    group = "root";
    mode = "0400";
    restartUnits = ["k3s.service"];
  };

  services.k3s = {
    enable = true;
    role = "agent";
    nodeName = "seraph";
    nodeIP = "10.1.2.194";
    serverAddr = "https://10.1.2.137:6443";
    tokenFile = config.sops.secrets."k3s/token".path;
    gracefulNodeShutdown = {
      enable = true;
      shutdownGracePeriod = "150s";
      shutdownGracePeriodCriticalPods = "10s";
    };
    extraFlags = [
      "--bind-address=10.1.2.194"
      "--flannel-iface=enp11s0"
      "--kube-proxy-arg=nodeport-addresses=10.1.2.194/32"
    ];
  };

  boot.kernelModules = ["br_netfilter" "overlay"];
  boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
  services.logind.settings.Login.InhibitDelayMaxSec = "150s";
  systemd.services.systemd-logind.reloadTriggers = [config.environment.etc."systemd/logind.conf".source];
  networking.firewall.extraInputRules = ''
    iifname "enp11s0" ip saddr 10.1.2.0/24 tcp dport 10250 accept
    iifname "enp11s0" ip saddr 10.1.2.0/24 udp dport 8472 accept
    iifname { "cni0", "flannel.1" } ip saddr 10.42.0.0/16 accept
  '';
  # 保留内部 API 请求的 Pod 地址，供 vexd 核验 Kubernetes 身份。
  networking.nftables.tables.vex-internal-api-source = {
    family = "ip";
    content = ''
      chain postrouting {
        type nat hook postrouting priority srcnat - 1; policy accept;
        iifname "cni0" oifname "enp11s0" ip saddr 10.42.1.0/24 ip daddr 10.1.2.137 tcp dport 8790 counter snat to ip saddr
      }
    '';
  };
  # API 响应按 Pod 路由经 flannel 返回，连接的请求路径经过 LAN。
  networking.firewall.extraReversePathFilterRules = ''
    iifname "flannel.1" ip saddr 10.1.2.137 ip daddr 10.42.1.0/24 tcp sport 8790 ct state established accept
  '';
  systemd.services.k3s = {
    environment.TMPDIR = "/var/cache/vex-k3s";
    serviceConfig = {
      CacheDirectory = "vex-k3s";
      CacheDirectoryMode = "0700";
    };
  };
}
