{
  config,
  lib,
  ...
}: let
  c = (import ../palettes/flat-white.nix).colors;
in {
  programs.lazygit.settings.gui.theme = lib.mkIf config.programs.lazygit.enable {
    activeBorderColor = [c.color4 "bold"];
    inactiveBorderColor = [c.color8];
    searchingActiveBorderColor = [c.color3 "bold"];
    optionsTextColor = [c.color6];
    selectedLineBgColor = [c.selection_bg];
    cherryPickedCommitFgColor = [c.color2];
    cherryPickedCommitBgColor = [c.color0];
    markedBaseCommitFgColor = [c.color5];
    markedBaseCommitBgColor = [c.color0];
    unstagedChangesColor = [c.color1];
    defaultFgColor = [c.foreground];
  };
}
