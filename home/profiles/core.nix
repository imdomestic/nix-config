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
    stateVersion = "24.11";
  };
  programs.home-manager.enable = true;
}
