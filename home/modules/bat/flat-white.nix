{
  config,
  lib,
  pkgs,
  ...
}: {
  programs.bat = lib.mkIf config.programs.bat.enable {
    config.theme = "flat-white";
    themes.flat-white.src = import ../palettes/flat-white-tmtheme.nix {inherit pkgs;};
  };
}
