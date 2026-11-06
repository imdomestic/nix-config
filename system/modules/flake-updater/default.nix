# Nightly flake input updates: a timer here moves the inputs in
# lib/flake-update-lanes.nix, builds and VM-tests what they change, and pushes
# what passes to main as the imdomestic-updater GitHub App. Why here and not a
# GitHub runner: docs/decisions.md#flake-updater.
#
#   systemctl start flake-updater                       a run now
#   sudo -u flake-updater flake-updater run --no-push   everything but the push
#   /var/lib/flake-updater/runs/<id>/                   log and report per run
{
  config,
  lib,
  pkgs,
  ...
}: let
  lanes = import ../../../lib/flake-update-lanes.nix;
  inputs = lanes.release ++ lanes.rolling;
  rootInputs = builtins.attrNames (builtins.fromJSON (builtins.readFile ../../../flake.lock)).nodes.root.inputs;
  state = "/var/lib/flake-updater";
  secret = name: config.sops.secrets."imdomestic-updater/${name}".path;

  githubKnownHosts = pkgs.writeText "github-known-hosts" ''
    github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
  '';
  # The two private inputs, one read-only deploy key each: GitHub does not let
  # one key be a deploy key on two repositories. git runs this as
  # `<this> git@github.com "git-upload-pack 'imdomestic/vex'"`.
  gitSsh = pkgs.writeShellScript "flake-updater-ssh" ''
    case "$*" in
      *imdomestic/wgconfigs*) key=${secret "wgconfigs-key"} ;;
      *imdomestic/vex*) key=${secret "vex-key"} ;;
      *) echo "flake-updater: no key for: $*" >&2; exit 1 ;;
    esac
    exec ${pkgs.openssh}/bin/ssh -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes \
      -o UserKnownHostsFile=${githubKnownHosts} -o StrictHostKeyChecking=yes "$@"
  '';

  flake-updater = pkgs.writeShellApplication {
    name = "flake-updater";
    runtimeInputs = with pkgs; [
      config.nix.package
      gitMinimal
      openssh
      jq
      curl
      openssl
      coreutils
      diffutils
      gnugrep
      gnused
    ];
    # Backticks inside single quotes are the reports' Markdown.
    excludeShellChecks = ["SC2016"];
    text =
      ''
        state=${state}
        repo=imdomestic/nix-config
        inputs=(${lib.escapeShellArgs inputs})
        app_client_id=Iv23liizAAb6qSZllI0D
        app_key=${secret "private-key"}
        bot_login='imdomestic-updater[bot]'
        bot_email='353309496+imdomestic-updater[bot]@users.noreply.github.com'
        fleet_nix=${./fleet.nix}
        # 16:00 to 19:00 UTC, midnight to 03:00 in China.
        budget=$((3 * 3600))
        export GIT_SSH_COMMAND=${gitSsh}
      ''
      + builtins.readFile ./flake-updater.sh;
  };
in {
  assertions = [
    {
      assertion = lib.all (i: lib.elem i rootInputs) inputs;
      message = "lib/flake-update-lanes.nix names inputs the flake does not have: ${toString (lib.subtractLists rootInputs inputs)}";
    }
  ];

  users.users.flake-updater = {
    isSystemUser = true;
    group = "flake-updater";
    home = state;
  };
  users.groups.flake-updater = {};

  sops.secrets = lib.genAttrs (map (n: "imdomestic-updater/${n}") ["private-key" "vex-key" "wgconfigs-key"]) (_: {
    owner = "flake-updater";
  });

  environment.systemPackages = [flake-updater];

  systemd.services.flake-updater = {
    description = "Update flake inputs, build and VM-test them, push what passes";
    wants = ["network-online.target"];
    after = ["network-online.target"];
    # A switch must not kill a run halfway through.
    restartIfChanged = false;
    environment = {
      HOME = state;
      XDG_CACHE_HOME = "/var/cache/flake-updater";
    };
    serviceConfig = {
      Type = "oneshot";
      User = "flake-updater";
      Group = "flake-updater";
      ExecStart = "${lib.getExe flake-updater} run";
      StateDirectory = "flake-updater";
      CacheDirectory = "flake-updater";
      # The script stops itself at its budget; this only catches a hang.
      TimeoutStartSec = "3h30min";
      Nice = 10;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      NoNewPrivileges = true;
    };
  };

  systemd.timers.flake-updater = {
    wantedBy = ["timers.target"];
    timerConfig.OnCalendar = "*-*-* 16:00:00 UTC";
  };
}
