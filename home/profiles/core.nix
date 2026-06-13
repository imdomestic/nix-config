{
  username,
  system,
  inputs,
  ...
}: let
  lib = inputs.nixpkgs.lib;
in {
  home = {
    inherit username;
    homeDirectory =
      if lib.hasInfix "darwin" system
      then "/Users/${username}"
      else "/home/${username}";
    stateVersion = "26.05";
  };
  programs.home-manager.enable = true;
}
