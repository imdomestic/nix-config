# Brings this host's system to a commit of this repository, built here from
# GitHub: `system-deploy check` says what a switch would do, and
# `system-deploy switch` does it in a unit of its own, so that it outlasts
# the shell and the service that asked for it, and goes back to the system
# that ran if a watched unit doesn't come up. Nothing runs it by itself
# (docs/decisions.md#auto-update). How to use it: AGENTS.md, "Deploys".
#
# A host lists this module itself, and says with `my.systemDeploy.checks`
# which units a switch is judged by. Not for a host with `buildOn`: it
# builds on the host.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.systemDeploy;
  names = lib.attrNames cfg.checks;
  # A bash associative array of one field of every check.
  table = field:
    lib.concatMapStringsSep " " (
      n: let
        v = cfg.checks.${n}.${field};
      in "[${lib.escapeShellArg n}]=${lib.escapeShellArg (
        if v == null
        then ""
        else toString v
      )}"
    )
    names;

  system-deploy = pkgs.writeShellApplication {
    name = "system-deploy";
    runtimeInputs = [
      config.nix.package
      pkgs.gitMinimal
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.gnused
      pkgs.util-linux
      config.systemd.package
    ];
    text =
      ''
        host=${lib.escapeShellArg config.my.host.name}
        state=/var/lib/system-deploy
        check_names=(${lib.escapeShellArgs names})
        declare -A check_unit=(${table "unit"})
        declare -A check_ready=(${table "ready"})
        declare -A check_before=(${table "before"})
        declare -A check_after=(${table "after"})
        declare -A check_irreversible=(${table "irreversible"})
      ''
      + builtins.readFile ./system-deploy.sh;
  };

  hook = description:
    lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      inherit description;
    };
in {
  options.my.systemDeploy.checks = lib.mkOption {
    default = {};
    description = ''
      What a switch is judged by, each a long-running unit of this host: one
      that isn't up after the switch sends the host back to the system that
      ran. With none, a switch is never undone.
    '';
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        unit = lib.mkOption {
          type = lib.types.str;
          example = "maxx.service";
          description = "The unit, which has a main process while it is up.";
        };
        ready = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "A regex of what its process logs once it serves; without one, lasting 20 seconds is enough.";
        };
        before = hook ''
          Run before a switch with the running system and the one to switch
          to: its lines go into the report, for what only this service can
          say of the change.
        '';
        after = hook ''
          Run once the unit is up, with its process id and the one it had
          before the switch (the same if it wasn't restarted): its lines go
          into the report.
        '';
        irreversible = hook ''
          Prints what a switch may change that the system before can't run
          on, a database's schema version say. If it differs after a switch
          that failed, the host isn't sent back, since that wouldn't help.
        '';
      };
    });
  };

  config.environment.systemPackages = [system-deploy];
}
