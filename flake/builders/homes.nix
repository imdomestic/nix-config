# homeConfigurations."hosts/<host>/<account>", aliased "<account>@<host>": one
# standalone Home Manager closure per account on every host, assembled from the
# files in the account's directory (`users.<account>.dir`) by name, in order:
#
#   ../_lib/home-base.nix   always: the plumbing, and my.home.tier
#   shell.nix               shell tier and up (flake/_lib/tiers.nix)
#   interactive.nix         interactive tier and up
#   gui-<platform>.nix      hosts with the gui role, shell tier and up
#   default.nix             always; the only file that must exist
#   dev.nix                 dev tier
#   <host>.nix              on that host
#
# A missing file is skipped. Nothing is registered: the file is the entry.
{
  config,
  inputs,
  lib,
  ...
}: let
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
    file = n: let
      f = entry.dir + "/${n}.nix";
    in
      lib.optional (builtins.pathExists f) f;
    default = entry.dir + "/default.nix";
  in
    lib.throwIfNot (builtins.pathExists default) "users.${accountName}: no default.nix in ${toString entry.dir}"
    inputs.home-manager.lib.homeManagerConfiguration {
      inherit (pkgs) pkgs;
      modules =
        hostModules hostName
        # Single injection point for the account name; everything else reads
        # `config.home.username` / `config.home.homeDirectory`.
        ++ [{home.username = accountName;}]
        ++ [../_lib/home-base.nix {my.home.tier = tier;}]
        ++ lib.optionals (at "shell") (file "shell")
        ++ lib.optionals (at "interactive") (file "interactive")
        ++ lib.optionals (lib.elem "gui" host.roles && at "shell") (file "gui-${platform}")
        ++ [default]
        ++ lib.optionals (at "dev") (file "dev")
        ++ file hostName;
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
