# Keeps this host's homes on main without anyone running `home-manager`: an
# hourly root job resolves main on GitHub, builds each account's
# `homeConfigurations."hosts/<host>/<account>"` here, and activates it as that
# account. Only for hosts that can build their own homes; the rest stay on
# deploy-rs (docs/decisions.md#home-sync).
#
#   home-sync              status of every account (root, like the rest)
#   home-sync run         one sync now; --dry-run builds and reports only
#   home-sync resume <u>   hand a held account back (see `held` below)
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.homeSync;
  state = "/var/lib/home-sync";

  home-sync = pkgs.writeShellApplication {
    name = "home-sync";
    runtimeInputs = [config.nix.package pkgs.gitMinimal pkgs.coreutils pkgs.util-linux pkgs.getent];
    text = ''
      state=${state}
      repo=imdomestic/nix-config
      host=${lib.escapeShellArg config.my.host.name}
      users=(${lib.escapeShellArgs cfg.users})
      # GitHub from China drops a fetch now and then, so the unit only goes
      # failed (and SystemdUnitFailed fires) once the same step has failed
      # this many runs in a row.
      threshold=3
      # Every sync is a Home Manager generation, and they live in the
      # account's ~/.local/state, where the system's nix.gc never expires them.
      keep=10
      dry=

      home_of() { getent passwd "$1" | cut -d: -f6; }

      # The generation Home Manager itself treats as running.
      current_of() { readlink -e "$(home_of "$1")/.local/state/home-manager/gcroots/current-home" || true; }

      profile_of() {
        local p
        p="$(home_of "$1")/.local/state/nix/profiles/home-manager"
        if [[ -e $p ]]; then echo "$p"; else echo "/nix/var/nix/profiles/per-user/$1/home-manager"; fi
      }

      failures() { cat "$state/$1.failures" 2>/dev/null || echo 0; }

      record() { if [[ -z $dry ]]; then echo "$2" >"$state/$1"; fi; }

      fail() {
        local n
        n=$(($(failures "$1") + 1))
        record "$1.failures" "$n"
        echo "$1: $2 (failure $n in a row)" >&2
      }

      # Held: the running generation is neither one home-sync activated nor
      # one it built, so someone switched by hand (`just hm`, `deploy-home`
      # from a working tree). Activating over it would quietly undo their
      # change; the hold ends once main builds to exactly what is running, or
      # on `home-sync resume`.
      held() {
        local current=$2 activated
        activated=$(cat "$state/$1.activated" 2>/dev/null || true)
        [[ -n $activated && $current != "$activated" && $current != "$(readlink -e "$state/$1.target" || true)" ]]
      }

      as_user() {
        local u=$1 home uid
        shift
        home=$(home_of "$u")
        uid=$(id -u "$u")
        # deploy-rs' home profiles activate with the same backup extension.
        local env=(HOME="$home" USER="$u" LOGNAME="$u" HOME_MANAGER_BACKUP_EXT=backup
          PATH="/run/wrappers/bin:/etc/profiles/per-user/$u/bin:/run/current-system/sw/bin")
        if [[ -d /run/user/$uid ]]; then
          env+=(XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus")
        fi
        (cd "$home" && setpriv --reuid="$u" --regid="$(id -g "$u")" --init-groups env -i "''${env[@]}" "$@")
      }

      sync_one() {
        local u=$1 rev=$2 current target was_held=
        current=$(current_of "$u")
        if [[ -z $dry && $(cat "$state/$u.rev" 2>/dev/null || true) == "$rev" ]]; then return 0; fi
        # Before the build: it replaces the $u.target link that held() reads.
        if held "$u" "$current"; then was_held=1; fi

        local link=(--out-link "$state/$u.target")
        if [[ -n $dry ]]; then link=(--no-link); fi
        if ! target=$(nix build "''${link[@]}" --print-out-paths \
          "github:$repo/$rev#homeConfigurations.\"hosts/$host/$u\".activationPackage"); then
          fail "$u" "building $rev failed"
          return 0
        fi

        if [[ $target == "$current" ]]; then
          echo "$u: up to date at ''${rev:0:12}"
          record "$u.activated" "$target"
        elif [[ -n $was_held ]]; then
          echo "$u: held at $current, which home-sync did not activate; 'home-sync resume $u' hands it back"
        elif [[ -n $dry ]]; then
          echo "$u: would activate $target"
        else
          echo "$u: activating ''${rev:0:12} ($target)"
          if ! as_user "$u" "$target/activate"; then
            fail "$u" "activating $target failed"
            return 0
          fi
          record "$u.activated" "$target"
          as_user "$u" nix-env --profile "$(profile_of "$u")" --delete-generations "+$keep" || true
        fi
        record "$u.rev" "$rev"
        rm -f "$state/$u.failures"
      }

      need_root() {
        if [[ $EUID -ne 0 ]]; then
          echo "home-sync $1: needs root" >&2
          exit 1
        fi
        mkdir -p "$state"
      }

      run() {
        need_root run
        if [[ ''${1:-} == --dry-run ]]; then dry=1; fi
        exec 9>"$state/lock"
        if ! flock -n 9; then
          echo "home-sync is already running"
          return 0
        fi

        local rev u bad=0
        if rev=$(timeout 60 git ls-remote "https://github.com/$repo" refs/heads/main | cut -f1) && [[ -n $rev ]]; then
          rm -f "$state/fetch.failures"
          for u in "''${users[@]}"; do sync_one "$u" "$rev"; done
        else
          fail fetch "cannot resolve main on github.com/$repo"
        fi

        for u in fetch "''${users[@]}"; do
          if (($(failures "$u") >= threshold)); then bad=1; fi
        done
        return "$bad"
      }

      status() {
        # Other accounts' homes are 0700: without root every one would read as held.
        need_root status
        local u current rev n s
        for u in "''${users[@]}"; do
          current=$(current_of "$u")
          rev=$(cat "$state/$u.rev" 2>/dev/null || true)
          n=$(failures "$u")
          if ((n > 0)); then
            s="failing ($n)"
          elif held "$u" "$current"; then
            s=held
          elif [[ -z $rev ]]; then
            s=pending
          else
            s=synced
          fi
          printf '%-10s %-12s %s\n' "$u" "$s" "''${rev:0:12}"
        done
        n=$(failures fetch)
        if ((n > 0)); then echo "resolving main: $n failures in a row"; fi
      }

      resume() {
        need_root resume
        if [[ " ''${users[*]} " != *" $1 "* ]]; then
          echo "home-sync: $1 is not synced on $host" >&2
          exit 1
        fi
        current_of "$1" >"$state/$1.activated"
        rm -f "$state/$1.rev"
        echo "$1: handed back; the next run (systemctl start home-sync) brings it to main"
      }

      case "''${1:-status}" in
        status) status ;;
        run) run "''${2:-}" ;;
        resume)
          if [[ $# -ne 2 ]]; then
            echo "usage: home-sync resume <account>" >&2
            exit 2
          fi
          resume "$2"
          ;;
        *)
          echo "usage: home-sync [status | run [--dry-run] | resume <account>]" >&2
          exit 2
          ;;
      esac
    '';
  };
in {
  options.my.homeSync.users = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = config.my.host.usernames;
    defaultText = lib.literalExpression "config.my.host.usernames";
    description = "Accounts whose homes this host keeps on main.";
  };

  config = {
    assertions = [
      {
        assertion = lib.all (u: lib.elem u config.my.host.usernames) cfg.users;
        message = "my.homeSync.users: every entry needs an account on ${config.my.host.name}";
      }
    ];

    environment.systemPackages = [home-sync];

    systemd.services.home-sync = {
      description = "Build and activate this host's homes from main";
      wants = ["network-online.target"];
      after = ["network-online.target"];
      # A switch must not kill a run in the middle of an activation.
      restartIfChanged = false;
      environment = {
        HOME = state;
        XDG_CACHE_HOME = "/var/cache/home-sync";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${lib.getExe home-sync} run";
        StateDirectory = "home-sync";
        CacheDirectory = "home-sync";
        Nice = 19;
        IOSchedulingClass = "idle";
        # One home evaluates in ~600 MB (h310, 2026-11-03); h610 has ~2 GB free.
        MemoryMax = "3G";
        TimeoutStartSec = "2h";
      };
    };

    systemd.timers.home-sync = {
      wantedBy = ["timers.target"];
      timerConfig = {
        OnCalendar = "hourly";
        RandomizedDelaySec = "20m";
        Persistent = true;
      };
    };
  };
}
