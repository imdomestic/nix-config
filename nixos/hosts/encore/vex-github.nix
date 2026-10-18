{config, ...}: {
  sops.secrets = {
    "vex/github-private-key" = {
      sopsFile = ../../../secrets/hosts/encore-vex-github-private-key;
      format = "binary";
      path = "/var/lib/vex/secrets/github-private-key.pem";
      owner = "root";
      group = "vexd";
      mode = "0640";
      restartUnits = ["vexd.service"];
    };
    "vex/github-client-secret" = {
      sopsFile = ../../../secrets/hosts/encore-vex-github-client-secret;
      format = "binary";
      path = "/var/lib/vex/secrets/github-client-secret";
      owner = "root";
      group = "vexd";
      mode = "0640";
      restartUnits = ["vexd.service"];
    };
  };
  services.vexd.settings.github.app = {
    app_id = 5366762;
    client_id = "Iv23li5DpGaXG30bErGB";
    private_key_file = config.sops.secrets."vex/github-private-key".path;
    client_secret_file = config.sops.secrets."vex/github-client-secret".path;
  };

  # 应答器继续根据实际 mc-router Pod 身份检查来源。
  networking.nftables.tables.vex-wake = {
    family = "inet";
    content = ''
      chain input {
        type filter hook input priority -10; policy accept;
        ip daddr 10.1.2.137 tcp dport 25566 iifname { "cni0", "flannel.1" } ip saddr { 10.42.0.0/24, 10.42.1.0/24 } accept
        ip daddr 10.1.2.137 tcp dport 25566 drop
      }
    '';
  };
}
