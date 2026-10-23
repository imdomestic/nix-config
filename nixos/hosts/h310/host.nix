{config, ...}: let
  m = config.flake.modules;
in {
  hosts.h310 = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["server"];
    tsName = "h310.inner.imdomestic.com";
    # h310 只有 tsName,没有 wireguard 地址,keyscan 走 tailnet。它的 22 端口是
    # Tailscale SSH 接的(banner 是 SSH-2.0-Tailscale),但透传出来的就是本机
    # /etc/ssh/ssh_host_ed25519_key —— 已和机器上那份逐字比对过。换台机器扫之前
    # 最好也核一遍,拿错了 sops 会在激活时才炸。
    ageKey = "age1a2j0kukmv638aeuyskcw6xa0sgejvmhja5p6etnn70h93270ap8q0dn6vt";
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "gaoji-cluster-worker.service"];
    };
    maxTier = "interactive";

    modules = [
      ./system.nix
      ./hardware-configuration.nix
      m.nixos.gaoji-worker
    ];

    users = {
      hank = {};
      kenneth = {};
      fendada = {};
      linwhite = {};
    };
  };
}
