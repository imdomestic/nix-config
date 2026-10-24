# homeConfigurations."hosts/<host>/<account>", aliased "<account>@<host>": one
# standalone Home Manager closure per account on every host. What goes in is
# composed from the account's entry in the `users` table, the host's account
# entry and the host itself, the shared tiers first:
#
#   core → shell → interactive        by tier (flake/_lib/tiers.nix)
#   gui profile                       gui role; the account's GUI layer
#   the account's own module
#   its dev module                    dev tier
#   its gui modules                   gui role; its own desktop tweaks
#   the host's extra modules for it
{
  config,
  inputs,
  lib,
  ...
}: let
  hm = config.flake.modules.homeManager;
  tiers = import ../_lib/tiers.nix {inherit lib;};
  hostModules = import ../_lib/host-modules.nix {inherit config lib;};
  nixpkgsConfig = import ../_lib/nixpkgs-config.nix;

  # One nixpkgs / nixpkgs-unstable eval shared by every account on a host.
  mkPkgs = host: let
    args = {
      inherit (host) system;
      overlays = lib.unique (host.homeOverlays ++ [inputs.nur.overlays.default]);
      config = nixpkgsConfig;
    };
  in {
    pkgs = import inputs.nixpkgs args;
    pkgsUnstable = import inputs.nixpkgs-unstable args;
  };

  mkHome = hostName: host: pkgs: accountName: account: let
    entry = config.users.${accountName} or (throw "hosts.${hostName}.users.${accountName}: no `users.${accountName}` entry (home/users/*/user.nix)");
    tier =
      tiers.min (
        if account.tier != null
        then account.tier
        else entry.tier
      )
      host.maxTier;
    at = tiers.atLeast tier;
    platform =
      if lib.hasSuffix "darwin" host.system
      then "darwin"
      else "linux";
    gui =
      if !(lib.elem "gui" host.roles && at "shell")
      then {
        profile = null;
        modules = [];
      }
      else if account.gui != null
      then account.gui
      else entry.gui.${platform};
  in
    inputs.home-manager.lib.homeManagerConfiguration {
      inherit (pkgs) pkgs;
      modules =
        hostModules hostName
        # Single injection point for the account name; everything else reads
        # `config.home.username` / `config.home.homeDirectory`.
        ++ [{home.username = accountName;}]
        ++ [hm.core]
        ++ lib.optional (at "shell") hm.shell
        ++ lib.optional (at "interactive") hm.interactive
        ++ lib.optional (gui.profile != null) gui.profile
        ++ [entry.module]
        ++ lib.optional (at "dev") (
          if entry.dev != null
          then entry.dev
          else hm.dev
        )
        ++ gui.modules
        ++ account.modules;
      # `inputs` and `system` stay specialArgs because they are used in
      # `imports`; host/account metadata lives in `config.my.host` / `config.home`.
      extraSpecialArgs = {
        inherit inputs;
        inherit (host) system;
        "pkgs-unstable" = pkgs.pkgsUnstable;
      };
    };
in {
  flake.homeConfigurations = lib.concatMapAttrs (hostName: host: let
    pkgs = mkPkgs host;
  in
    lib.concatMapAttrs (accountName: account: let
      cfg = mkHome hostName host pkgs accountName account;
    in {
      # Canonical name — what `just hm` and the deploy nodes resolve.
      "hosts/${hostName}/${accountName}" = cfg;
      # What the home-manager CLI looks up by itself when given a bare flake
      # reference (it tries `$USER@$(hostname)`, then `$USER`), so on the
      # machine itself no attribute path has to be spelled out.
      "${accountName}@${hostName}" = cfg;
    })
    host.users)
  config.hosts;
}
