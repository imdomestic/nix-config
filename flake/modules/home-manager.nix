# Home Manager modules picked by name: `config.flake.modules.homeManager.<name>`.
# The tier and gui profiles are what flake/builders/homes.nix composes from;
# the rest are what host or account entries add. Account modules register
# themselves in home/users/*/user.nix.
{
  flake.modules.homeManager = {
    # tiers (flake/_lib/tiers.nix)
    core = ../../home/profiles/core.nix;
    shell = ../../home/profiles/shell.nix;
    interactive = ../../home/profiles/interactive.nix;
    dev = ../../home/profiles/dev.nix;

    # gui bundles
    gui-common = ../../home/profiles/gui/common.nix;
    gui-darwin = ../../home/profiles/gui/darwin.nix;
    gui-linux = ../../home/profiles/gui/linux.nix;

    ibus = ../../home/modules/ibus;
    opencode-local-bonsai = ../../home/modules/opencode/local-bonsai.nix;
    postgresql = ../../home/modules/postgresql;
    tailscale = ../../home/modules/tailscale;
  };
}
