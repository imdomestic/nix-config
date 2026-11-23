{
  lib,
  inputs,
  config,
  pkgs,
  pkgs-unstable,
  system,
  ...
}: {
  # NixOS only; macOS hosts start from system/profiles/darwin.nix.
  imports = [
    ../modules/nix.nix
    ../modules/users.nix
    ../modules/home-manager-cli.nix
    # sshd 只认 key,不管哪台、谁打开的 sshd。
    ../modules/ssh/policy.nix
    # 默认关;路由器和有公网地址的机器用 my.ddns 打开。
    ../modules/ddns-go
    inputs.sops-nix.nixosModules.sops
    # tailscale + Tailscale SSH。模块自己按 my.host.tsName 决定开不开,所以无条件
    # import。
    ../modules/tailscale
  ];

  # Host metadata comes from config.my.host (see flake/_lib/host-options.nix);
  # the specialArgs that remain are set in flake/builders/systems.nix.
  nixpkgs.hostPlatform = lib.mkDefault system;
  networking.hostName = lib.mkDefault config.my.host.name;

  # The LTS kernel needs a reboot for every point release too, and its
  # backports broke the out-of-tree bcachefs module; see
  # docs/decisions.md#latest-kernel.
  boot.kernelPackages = lib.mkDefault pkgs.linuxPackages_latest;
  # 26.05's nvidia driver does not build on the newest kernel; unstable's,
  # compiled against our kernel, does. Only read where nvidia is enabled.
  hardware.nvidia.package = lib.mkDefault (pkgs-unstable.linuxPackagesFor config.boot.kernelPackages.kernel).nvidiaPackages.production;

  boot.loader = {
    # mkDefault: a host with a small ESP (r6s) sets its own.
    systemd-boot.configurationLimit = lib.mkIf config.boot.loader.systemd-boot.enable (lib.mkDefault 10);
    grub.configurationLimit = lib.mkIf config.boot.loader.grub.enable (lib.mkDefault 10);
    generic-extlinux-compatible.configurationLimit = lib.mkIf config.boot.loader.generic-extlinux-compatible.enable (lib.mkDefault 10);
  };

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
