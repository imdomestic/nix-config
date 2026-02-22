{
  inputs,
  pkgs,
  lib,
  system,
  username,
  ...
}: {
  home.packages = with pkgs; [
    zoxide
    curl
    wireguard-tools
    just
    tmux
    bat
    neofetch
    fastfetch
    ripgrep
    fd
    eza
    duf
    btop
    zinit
    nix-output-monitor
    tree
    file
    iperf3
    which
    wget
    sops

    # archives
    zip
    xz
    unzip
    p7zip
    zstd
  ];

  programs.yazi = {
    enable = true;
    settings = {
      theme = {
        flavor = {
          dark = "kanso-ink";
          light = "kanso-pearl";
        };
      };
    };
    flavors = {
      kanso-ink = ../modules/yazi/kanso-ink.yazi;
      kanso-pearl = ../modules/yazi/kanso-pearl.yazi;
    };
  };

  programs.zsh = {
    enable = true;
  };

  programs.fzf = {
    enable = true;
    defaultOptions = ["--height 40%" "--layout=reverse" "--border"];
  };

  programs.zoxide = {
    enable = true;
    enableNushellIntegration = true;
    # options = ["--cmd cd"];
  };

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };

  programs.nh = {
    enable = true;
    clean.enable = false;
    clean.extraArgs = "--keep-since 4d --keep 3";
    flake =
      if lib.hasInfix "linux" system
      then "/home/${username}/.config/nix-config"
      else "/Users/${username}/.config/nix-config";
  };
}
