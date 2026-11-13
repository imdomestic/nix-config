# fendada 在 encore 上的配置：暂时借用 linwhite 的桌面环境与视觉样式。
{config, ...}: {
  imports = [
    ../linwhite/encore.nix
    ../linwhite/profiles/gui-linux.nix
    ../linwhite/modules/ghostty/settings.nix
    ../linwhite/modules/wezterm.nix
    ../linwhite/modules/starship.nix
    ../linwhite/modules/zsh.nix
    ../linwhite/modules/tmux.nix
    ../linwhite/modules/fastfetch.nix
    ../linwhite/modules/yazi
    ../linwhite/modules/flat-white/fzf.nix
    ../linwhite/modules/flat-white/bat.nix
    ../linwhite/modules/flat-white/btop.nix
    ../linwhite/modules/flat-white/yazi.nix
    ../linwhite/modules/flat-white/vicinae.nix
  ];

  programs.bat.enable = true;
  programs.btop.enable = true;
  programs.wezterm.enable = config.programs.ghostty.enable;
}
