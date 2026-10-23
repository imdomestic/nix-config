{config, ...}: {
  flake.modules.homeManager.nix = ./default.nix;

  users.nix = {
    tier = "minimal";
    module = config.flake.modules.homeManager.nix;
  };
}
