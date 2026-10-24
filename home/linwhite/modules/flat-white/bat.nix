{
  config,
  lib,
  pkgs,
  ...
}: {
  programs.bat = lib.mkIf config.programs.bat.enable {
    config.theme = "flat-white";
    themes.flat-white.src = import ./tmtheme.nix {inherit pkgs;};
  };
}
