{
  config,
  lib,
  pkgs,
  ...
}: let
  domain = "vex.inner.imdomestic.com";
  orderUnit = "acme-order-renew-${domain}";
  stateDirectories = config.systemd.services.${orderUnit}.serviceConfig.StateDirectory;
  accountDirectories = builtins.filter (lib.hasPrefix "acme/.lego/accounts/") stateDirectories;
  certificateDirectories = builtins.filter (lib.hasPrefix "acme/.lego/${domain}/") stateDirectories;
  workspace = name: "/var/cache/vex-acme/${name}";
  workConfig = name: {
    environment.TMPDIR = workspace name;
    serviceConfig = {
      PrivateTmp = lib.mkForce false;
      WorkingDirectory = lib.mkForce (workspace name);
      CacheDirectory = "vex-acme/${name}";
      CacheDirectoryMode = "0700";
    };
  };
in {
  assertions = [
    {
      assertion = builtins.length accountDirectories == 1 && builtins.length certificateDirectories == 1;
      message = "Vex ACME requires one account and certificate state directory";
    }
    {
      assertion = config.networking.nftables.enable;
      message = "Vex internal HTTP restriction requires nftables";
    }
  ];

  sops.secrets."vex/acme-cloudflare.env" = {
    sopsFile = ../../secrets/hosts/encore-acme.env;
    format = "binary";
    mode = "0400";
  };
  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
    certs.${domain} = {
      server = "https://acme-v02.api.letsencrypt.org/directory";
      dnsProvider = "cloudflare";
      dnsResolver = "1.1.1.1:53";
      environmentFile = config.sops.secrets."vex/acme-cloudflare.env".path;
      group = "vexd";
      postRun = ''
        if ${pkgs.systemd}/bin/systemctl is-active --quiet vexd.service; then
          ${pkgs.systemd}/bin/systemctl --no-block reload vexd.service
        fi
      '';
    };
  };

  # ACME 使用独立工作目录，保留原生签发、续期与证书权限处理。
  systemd.services.acme-setup = lib.mkMerge [
    (workConfig "setup")
    {
      serviceConfig.BindPaths = lib.mkForce ["/var/lib/acme/.minica:${workspace "setup"}/ca"];
    }
  ];
  systemd.services."acme-${domain}" = lib.mkMerge [
    (workConfig "prepare")
    {
      serviceConfig.BindPaths = lib.mkForce [
        "/var/lib/acme/.minica:${workspace "prepare"}/ca"
        "/var/lib/acme/${domain}:${workspace "prepare"}/out"
      ];
    }
  ];
  systemd.services.${orderUnit} = lib.mkMerge [
    (workConfig "order")
    {
      serviceConfig.BindPaths = lib.mkForce [
        "/var/lib/${builtins.head accountDirectories}:${workspace "order"}/accounts"
        "/var/lib/acme/${domain}:${workspace "order"}/out"
        "/var/lib/${builtins.head certificateDirectories}:${workspace "order"}/certificates"
      ];
    }
  ];
  systemd.services.vexd = {
    after = ["${orderUnit}.service"];
    wants = ["${orderUnit}.service"];
    preStart = ''
      ${pkgs.openssl}/bin/openssl verify -CAfile ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt \
        -untrusted /var/lib/acme/${domain}/chain.pem /var/lib/acme/${domain}/fullchain.pem
      ${pkgs.openssl}/bin/openssl x509 -in /var/lib/acme/${domain}/fullchain.pem -noout -checkhost ${domain}
    '';
  };

  # 此规则先于普通防火墙放行；项目身份还由 vexd 内部监听器核验。
  networking.firewall.extraReversePathFilterRules = ''
    iifname "wlo1" ip saddr 10.42.1.0/24 ip daddr 10.1.2.137 tcp dport 8790 accept
  '';
  networking.nftables.tables.vex-internal-api = {
    family = "inet";
    content = ''
      chain input {
        type filter hook input priority -10; policy accept;
        ip daddr 10.1.2.137 tcp dport 8790 iifname "lo" accept
        ip daddr 10.1.2.137 tcp dport 8790 iifname { "cni0", "flannel.1" } ip saddr { 10.42.0.0/24, 10.42.1.0/24 } accept
        ip daddr 10.1.2.137 tcp dport 8790 iifname "wlo1" ip saddr 10.42.1.0/24 accept
        ip daddr 10.1.2.137 tcp dport 8790 drop
      }
    '';
  };
}
