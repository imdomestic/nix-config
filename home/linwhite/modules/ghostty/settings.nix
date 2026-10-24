{
  config,
  lib,
  pkgs,
  ...
}: let
  gui = config.programs.ghostty.enable;
  darwin = pkgs.stdenv.isDarwin;
in {
  imports = [../flat-white/ghostty.nix];
  # aegis 未装 Homebrew cask，使用原生 HM package 安装官方 macOS 二进制。
  programs.ghostty.package = lib.mkIf (gui && darwin) (lib.mkForce pkgs.ghostty-bin);

  # 共用 hank 的终端集成；尺寸、透明度和留白来自 linwhite 的 WezTerm。
  programs.ghostty.settings = lib.mkIf gui ({
      font-size = lib.mkForce 14;
      background-opacity = lib.mkForce 0.7;
      # 让 tmux 等程序绘制的背景使用窗口透明度。
      background-opacity-cells = true;
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
}
