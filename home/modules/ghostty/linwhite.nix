{
  config,
  lib,
  pkgs,
  ...
}: let
  gui = config.programs.ghostty.enable;
  darwin = pkgs.stdenv.isDarwin;
in {
  # aegis 未装 Homebrew cask，使用原生 HM package 安装官方 macOS 二进制。
  programs.ghostty.package = lib.mkIf (gui && darwin) (lib.mkForce pkgs.ghostty-bin);

  # 共用 hank 的终端集成；尺寸、透明度和留白来自 linwhite 的 WezTerm。
  programs.ghostty.settings = lib.mkIf gui ({
      font-family = lib.mkBefore ["Recursive"];
      font-size = lib.mkForce 14;
      background-opacity = lib.mkForce 0.7;
      window-width = 150;
      window-height = 50;
      window-padding-x = 2;
      window-padding-y = 0;
      window-padding-balance = true;
      window-decoration = lib.mkForce false;
      unfocused-split-opacity = 0.8;
      keybind = lib.mkAfter [
        "ctrl+shift+h=goto_split:left"
        "ctrl+shift+j=goto_split:down"
        "ctrl+shift+k=goto_split:up"
        "ctrl+shift+l=goto_split:right"
      ];
    }
    // lib.optionalAttrs darwin {
      macos-titlebar-style = lib.mkForce "hidden";
    });

  programs.wezterm = lib.mkIf gui {
    enable = true;
    settings = {
      font = lib.generators.mkLuaInline ''wezterm.font_with_fallback({"Recursive", "RecMonoSmCasual Nerd Font Mono", ${
          if darwin
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
  };
}
