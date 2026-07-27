# Single source of truth for pinning the indirect `nixpkgs` flake refs to the
# revs this configuration was built with, so `nix run nixpkgs#x` stops chasing
# the branch head and refetching the source plus a whole new closure every time
# tarball-ttl expires.
#
# Spelled out as github refs rather than the `flake = inputs.nixpkgs` shorthand
# on purpose: that shorthand resolves to `type = "path"`, and a path entry leaks
# a machine-local `path:/nix/store/...-source` into the flake.lock of any project
# whose input reads `nixpkgs.url = "nixpkgs"`, which no other machine can fetch.
# A github ref carrying rev + narHash pins exactly as hard, still resolves
# offline out of the fetcher cache, and stays portable.
{inputs}: let
  lib = inputs.nixpkgs.lib;

  githubRef = flake: {
    type = "github";
    owner = "NixOS";
    repo = "nixpkgs";
    inherit (flake) rev narHash;
  };

  entries = {
    nixpkgs = githubRef inputs.nixpkgs;
    nixpkgs-local = githubRef inputs.nixpkgs;
    nixpkgs-unstable = githubRef inputs.nixpkgs-unstable;
  };
in {
  inherit entries;

  # Shape expected by `nix.registry` (NixOS, nix-darwin, home-manager) and by
  # `determinateNix.registry`.
  registry = lib.mapAttrs (_: to: {inherit to;}) entries;

  # For platforms with no such option. /etc/nix/registry.json is read
  # unconditionally by Nix as the system tier, above the global registry.
  etcJSON = builtins.toJSON {
    version = 2;
    flakes =
      lib.mapAttrsToList (id: to: {
        from = {
          type = "indirect";
          inherit id;
        };
        inherit to;
        exact = true;
      })
      entries;
  };
}
