# Keep native module-generated settings; adapt only applications requiring IP literals.
{
  pkgs,
  package,
  programs,
  kind,
  tsName,
}: let
  inherit (pkgs) lib;
in
  pkgs.symlinkJoin {
    name = "${package.name}-tailscale-bind";
    paths = [package];
    meta = package.meta;
    nativeBuildInputs = [pkgs.makeWrapper];
    postBuild =
      lib.concatMapStringsSep "\n" (program: ''
        rm "$out/bin/${program}"
        makeWrapper ${pkgs.python3}/bin/python3 "$out/bin/${program}" \
          --add-flags ${lib.escapeShellArg "${../nixos/modules/tailscale/resolve-bind.py} ${kind} ${package}/bin/${program}"} \
          --set TAILSCALE_BIND_IP ${pkgs.iproute2}/bin/ip \
          --set TAILSCALE_BIND_NAME ${lib.escapeShellArg tsName}
      '')
      programs;
  }
