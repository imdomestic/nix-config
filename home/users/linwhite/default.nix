{
  lib,
  inputs,
  system,
  pkgs,
  config,
  ...
}: let
  isDarwin = pkgs.stdenv.isDarwin;
  # 仓库 fonts/ 里的 Recursive(静态、等宽)。放进 home.packages 后,Home Manager
  # 会把 share/fonts 复制到 ~/Library/Fonts/HomeManager。
  recursiveFonts = pkgs.runCommandLocal "recursive-fonts" {} ''
    install -Dm444 -t $out/share/fonts/truetype ${../../../fonts}/*.ttf
  '';
in {
  imports = [
    ../../modules/tmux
    # 精简版 nixvim(nix 支持常开);dev.nix 会把 my.nixvim.dev.enable 打开
    ../../modules/nixvim/linwhite
    # MC 开发脚本（mc-client / mc-server-remote），模块内部只对 encore 生效
    ../../modules/chorus
  ];

  # 普通 substituters 覆盖系统列表，仅影响当前用户（包括共用机器）。
  nix = {
    package = pkgs.nix;
    settings.substituters = import ../../../lib/nix-substituters.nix {
      useChinaMirror = false;
    };
  };

  home.sessionVariables = {
    ZDOTDIR =
      if lib.hasInfix "darwin" system
      then "/Users/linwhite/.config/zsh"
      else "/home/linwhite/.config/zsh";
  };

  xdg.configFile = {
    zsh.source = inputs.zsh-linwhite.outPath;
    # nvim.source = inputs.nixvim.outPath;
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
  home.packages = lib.optionals isDarwin [
    (pkgs.callPackage ../../../pkgs/kazumi {})
    recursiveFonts
  ];

  # tmux/zsh 的字体就是终端的字体。mkBefore 把 Recursive 排到共享模块那串
  # fallback 前面:缺的 Nerd Font 图标落到 RecMonoSmCasual,中文落到 PingFang SC。
  programs.ghostty.settings.font-family = lib.mkIf isDarwin (lib.mkBefore ["Recursive"]);

  # macOS 不允许换界面字体(SF);能改的只有 AppKit 的用户字体和等宽字体,
  # 不自带字体设置的应用(TextEdit 新文档之类)会用它们。
  targets.darwin.defaults.NSGlobalDomain = lib.mkIf isDarwin {
    NSFont = "Recursive-Regular";
    NSFixedPitchFont = "Recursive-Regular";
  };

  programs.zsh.enable = true;

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };

  programs.starship = {
    enable = true;
    enableTransience = true;
    enableZshIntegration = true;
  };
}
