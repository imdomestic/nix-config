{config, ...}: {
  flake.modules.homeManager.genisys = ./default.nix;

  users.genisys = {
    tier = "minimal";
    module = config.flake.modules.homeManager.genisys;
  };
}
