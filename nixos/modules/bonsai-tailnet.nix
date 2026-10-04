{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.bonsaiNinfer;
  bonsai = import ../../lib/bonsai-models.nix;
  gateway = (pkgs.callPackage inputs.llama-swap-proxy {}).overrideAttrs (old: {
    patches = (old.patches or []) ++ [
      ../hosts/wsl/llama-swap-proxy-backend-timings.patch
      ../../scripts/patches/llama-swap-proxy-api-key.patch
    ];
    vendorHash = "sha256-LS+PBnNbtSr3cibu8Nb6DEkko78EVO2l+1hxgsj5Iiw=";
  });
  swapConfig = (pkgs.formats.yaml {}).generate "bonsai-gateway.yaml" config.services.llama-swap.settings;
  runner = pkgs.writeShellApplication {
    name = "run-bonsai-tailnet-gateway";
    runtimeInputs = [pkgs.coreutils pkgs.tailscale];
    text = ''
      tailnet_address="$(tailscale ip -4 | head -n 1)"
      test -n "$tailnet_address"
      exec ${lib.getExe gateway} \
        --listen "$tailnet_address:${toString bonsai.port}" \
        --upstream http://127.0.0.1:${toString bonsai.port} \
        --config ${swapConfig} \
        --api-key-env BONSAI_API_KEY \
        --disable-return-progress-injection \
        --sessions-dir ${bonsai.directory}/gateway \
        --default-user ${lib.escapeShellArg (lib.head config.my.host.usernames)} \
        --opencode-hostname ${lib.escapeShellArg "${config.my.host.tsName}:${toString bonsai.port}"}
    '';
  };
in {
  options.services.bonsaiNinfer.tailnet.enable = lib.mkEnableOption "Bonsai access from aegis over Tailscale";
  config = lib.mkIf (cfg.enable && cfg.tailnet.enable) {
    assertions = [{
      assertion = config.services.tailscale.enable && config.my.host.tsName != null;
      message = "Bonsai 的远程网关需要 Tailscale 与主机注册名称。";
    }];
    users.groups.bonsai-gateway = {};
    users.users.bonsai-gateway = {isSystemUser = true; group = "bonsai-gateway";};
    systemd.tmpfiles.rules = ["d ${bonsai.directory}/gateway 0750 bonsai-gateway bonsai-gateway -"];
    systemd.services.bonsai-tailnet-gateway = {
      description = "Authenticated Bonsai gateway for aegis";
      wantedBy = ["multi-user.target"];
      wants = ["tailscaled.service"];
      requires = ["llama-swap.service"];
      after = ["tailscaled.service" "llama-swap.service"];
      serviceConfig = {
        Type = "simple";
        User = "bonsai-gateway";
        Group = "bonsai-gateway";
        ExecStart = lib.getExe runner;
        EnvironmentFile = config.sops.templates."bonsai-environment".path;
        Restart = "on-failure";
        RestartSec = 5;
        NoNewPrivileges = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = ["${bonsai.directory}/gateway"];
      };
    };
    my.tailscale.guardedTCPServices.bonsai-tailnet-gateway = [bonsai.port];
    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [bonsai.port];
    # 100.64.0.25 已通过 aegis 的 Tailscale 状态核实。
    networking.nftables.tables.bonsai-clients = {
      family = "inet";
      content = ''
        chain input {
          type filter hook input priority -11; policy accept;
          iifname "tailscale0" ip saddr != 100.64.0.25 tcp dport ${toString bonsai.port} counter drop
          iifname "tailscale0" meta nfproto ipv6 tcp dport ${toString bonsai.port} counter drop
        }
      '';
    };
  };
}
