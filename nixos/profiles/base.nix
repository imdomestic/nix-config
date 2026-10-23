{
  lib,
  inputs,
  config,
  system,
  ...
}: {
  # NixOS only; macOS hosts start from darwin/profiles/base.nix.
  imports = [
    ../modules/nix.nix
    ../modules/users.nix
    ../modules/home-manager-cli.nix
    inputs.sops-nix.nixosModules.sops
    # tailscale + Tailscale SSH。模块自己按 my.host.tsName 决定开不开,所以无条件
    # import。
    ../modules/tailscale
  ];

  # Host metadata comes from config.my.host (see modules/shared/host-options.nix);
  # the specialArgs that remain are set in flake/builders/systems.nix.
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
