# Where each fleet service runs; the entries are in ../placements.nix. Clients
# derive the address from `config.my.fleet.placements.<service>`, so moving a
# service is one line there plus moving its server module.
{
  config,
  lib,
  ...
}: let
  inherit (lib) mkOption types;
in {
  options.placements = mkOption {
    type = types.attrsOf (types.submodule {
      options = {
        host = mkOption {
          type = types.str;
          description = "Registry name of the host the service runs on.";
        };
        port = mkOption {
          type = types.nullOr types.port;
          default = null;
          description = "Port clients connect to, when there is a single one.";
        };
      };
    });
    default = {};
    description = "Service placements, by service name.";
  };

  # Resolved once here so clients never re-derive an address.
  options.resolvedPlacements = mkOption {
    type = types.attrsOf types.raw;
    readOnly = true;
    internal = true;
  };

  config.resolvedPlacements =
    lib.mapAttrs (svc: p: let
      host = config.hosts.${p.host} or (throw "placements.${svc}: no host `${p.host}` in the registry");
    in {
      inherit (p) host port;
      inherit (host) tsName;
    })
    config.placements;
}
