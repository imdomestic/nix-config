{
  lib,
  pkgs,
  config,
  ...
}: let
  isDarwin = pkgs.stdenv.isDarwin;
in {
  imports = [
    ./modules/tmux.nix
    ./modules/zsh.nix
    ./modules/starship.nix
    ./modules/ghostty/settings.nix
    ./modules/wezterm.nix
    ./modules/yazi
    ./modules/fzf.nix
    ./modules/flat-white/fzf.nix
    ./modules/flat-white/bat.nix
    ./modules/flat-white/btop.nix
    ./modules/flat-white/yazi.nix
    ./modules/flat-white/vicinae.nix
    # 精简版 nixvim(nix 支持常开);dev.nix 会把 my.nixvim.dev.enable 打开
    ./modules/nixvim
  ];

  # 与 shell 导出的 XDG_CONFIG_HOME 一致，尤其是 macOS 上的 lazygit。
  xdg.enable = true;

  # 普通 substituters 覆盖系统列表，仅影响当前用户（包括共用机器）。
  nix = {
    package = pkgs.nix;
    settings.substituters = import ../../../lib/nix-substituters.nix {};
  };

  programs.git = {
    enable = true;
    settings = {
      user.name = "linwhite";
      user.email = "linwhite@linwhite.top";
    };
  };

  # pkgs/kazumi 是上游 macOS dmg 的二进制包,只在 darwin 上有;Linux 上要用
  # 的话 nixpkgs 自带从源码构建的 kazumi。
  home.packages =
    lib.optional isDarwin (pkgs.callPackage ../../../pkgs/kazumi {});

  # macOS 不允许换界面字体(SF);能改的只有 AppKit 的用户字体和等宽字体,
  # 不自带字体设置的应用(TextEdit 新文档之类)会用它们。
  targets.darwin.defaults.NSGlobalDomain = lib.mkIf isDarwin {
    # RecMonoSmCasual Nerd Font Mono(system/modules/nerdfonts)。
    NSFont = "RecMonoSmCasualNFM";
    NSFixedPitchFont = "RecMonoSmCasualNFM";
  };

  programs.bat.enable = true;
  programs.btop.enable = true;
  programs.wezterm.enable = config.programs.ghostty.enable;

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };
}
