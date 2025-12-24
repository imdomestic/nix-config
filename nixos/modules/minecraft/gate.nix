{
  config,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.gate];

  environment.etc."gate/config.yml".text = ''
    config:
      bind: 0.0.0.0:25555
    lite:
      enabled: true
      routes:
        - host: "*"
          backend: 10.0.0.66:25565
          proxyProtocol: true
          fallback:
            motd: |
              §cBackend offline
              §eTry again later
            version:
              name: '§cOffline'
              protocol: -1
  '';

  users.groups.gate = {};
  users.users.gate = {
    isSystemUser = true;
    group = "gate";
  };

  systemd.services.gate = {
    description = "Minekube Gate (Lite Mode)";
    wants = ["network-online.target" "wg-quick-wg0.service"];
    after = ["network-online.target" "wg-quick-wg0.service"];

    wantedBy = ["multi-user.target"];

    serviceConfig = {
      User = "gate";
      Group = "gate";

      StateDirectory = "gate";
      WorkingDirectory = "/var/lib/gate";

      ExecStart = "${pkgs.gate}/bin/gate -c /etc/gate/config.yml";
      Restart = "always";
      RestartSec = "2s";

      # 基本加固（可删）
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
    };
  };
}
