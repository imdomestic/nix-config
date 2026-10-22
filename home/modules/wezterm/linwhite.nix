{
  config,
  lib,
  pkgs,
  ...
}: {
  imports = [./flat-white.nix];
  programs.wezterm.settings = lib.mkIf config.programs.wezterm.enable {
    font = lib.generators.mkLuaInline ''wezterm.font_with_fallback({"Recursive", "RecMonoSmCasual Nerd Font Mono", ${
        if pkgs.stdenv.isDarwin
        then ''"Menlo", "Apple Color Emoji", "azuki_font", "PingFang SC"''
        else ''"DejaVu Sans Mono", "Noto Color Emoji", "Noto Sans CJK SC"''
      }})'';
    font_size = 14;
    initial_cols = 150;
    initial_rows = 50;
    text_background_opacity = 0.6;
    window_background_opacity = 0.7;
    macos_window_background_blur = 20;
    window_decorations = "RESIZE";
    enable_tab_bar = false;
    max_fps = 120;
    animation_fps = 120;
    window_padding = {
      left = 2;
      right = 2;
      top = 0;
      bottom = 0;
    };
    inactive_pane_hsb = {
      saturation = 0.9;
      brightness = 0.8;
    };
  };
}
