{
  lib,
  inputs,
  config,
  system,
  ...
}: {
  imports =
    [
      ../modules/nix.nix
      ../modules/users.nix
      ../modules/home-manager-cli.nix
    ]
    ++ lib.optionals (lib.hasInfix "linux" system) [
      inputs.sops-nix.nixosModules.sops
      # tailscale + Tailscale SSH。模块自己按 my.host.tsIp 决定开不开,所以
      # 无条件 import。**只给 linux** —— 它用的 services.tailscale.extraSetFlags
      # 是 NixOS 的选项,nix-darwin 那边没有(darwin 走 darwin/profiles/base.nix,
      # 现在够不到这里,但这个文件里已经有 darwin 分支了,别留这个雷)。
      ../modules/tailscale
    ]
    ++ lib.optionals (lib.hasInfix "darwin" system) [
      inputs.sops-nix.darwinModules.sops
    ];

  # Host metadata comes from config.my.host (see modules/shared/host-options.nix);
  # legacy module args are bridged centrally in lib/mkConfigurations.nix.
  nixpkgs.hostPlatform = lib.mkDefault system;
  networking.hostName = lib.mkDefault config.my.host.name;

  # Per-host secrets live in secrets/hosts/<name>.yaml (encrypted to that
  # host's ssh-derived age key, see .sops.yaml); fall back to the shared file.
  sops = {
    defaultSopsFile = let
      perHost = ../../secrets/hosts + "/${config.my.host.name}.yaml";
    in
      lib.mkDefault (
        if builtins.pathExists perHost
        then perHost
        else ../../secrets/secrets.yaml
      );
    defaultSopsFormat = "yaml";
  };
}
