# Home Manager modules picked by name: `config.flake.modules.homeManager.<name>`.
# The tier profiles are what flake/builders/homes.nix composes from.
# Everything an account loads registers itself in home/users/<account>/user.nix.
{
  flake.modules.homeManager = {
    # tiers (flake/_lib/tiers.nix)
    core = ../../home/profiles/core.nix;
    shell = ../../home/profiles/shell.nix;
    interactive = ../../home/profiles/interactive.nix;
    dev = ../../home/profiles/dev.nix;
  };
}
