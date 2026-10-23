{config, ...}: {
  flake.modules.homeManager.genisys = ./default.nix;

  users.genisys = {
    tier = "minimal";
    module = config.flake.modules.homeManager.genisys;
    sshKeys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMS1EJ44RHe9nmRqGwz/b/lih+KNxyJwvPaAtCRLRJTZ genisys@HUAWEI-MateBook-Pro.local"];
  };
}
