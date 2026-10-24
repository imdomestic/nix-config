{
  config,
  lib,
  pkgs,
  ...
}: let
  # Shader source is a GPU program asset; Ghostty configuration stays in settings.
  shader = pkgs.writeText "neovide-cursor.glsl" ''
    #define PIXIE_Y_SIGN ${
      if pkgs.stdenv.isDarwin
      then "1.0"
      else "-1.0"
    }
    ${builtins.readFile ./shaders/neovide-cursor.glsl}
  '';
in {
  options.my.ghostty.neovideCursor.enable = lib.mkEnableOption "Neovide-style cursor smear and pixiedust";

  config = lib.mkIf (config.my.ghostty.neovideCursor.enable && config.programs.ghostty.enable) {
    # Stateless approximation and tuning: docs/ghostty-cursor.md.
    programs.ghostty.settings = {
      custom-shader = ["${shader}"];
      custom-shader-animation = true;
    };
  };
}
