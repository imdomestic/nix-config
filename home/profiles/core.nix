{
  lib,
  config,
  ...
}: {
  home = {
    homeDirectory =
      if lib.hasInfix "darwin" config.my.host.system
      then "/Users/${config.home.username}"
      else "/home/${config.home.username}";
    stateVersion = "26.05";
  };
  programs.home-manager.enable = true;
}
