{
  inputs,
  pkgs,
  lib,
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
    eza
    fzf
    duf
    btop
    zinit
    nix-output-monitor
    tree
    file
    iperf3
    which
    wget

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

  programs.tmux = {
    enable = true;
    terminal = "tmux-256color";
    mouse = true;
    plugins = [ pkgs.tmuxPlugins.dotbar ];
    extraConfig = ''
      set-option -ga terminal-overrides ",*256col*:Tc"

      setw -g xterm-keys on
      set -s escape-time 0
      set -sg repeat-time 300
      set -s focus-events on
      set -sg exit-empty on

      set -q -g status-utf8 on
      setw -q -g utf8 on

      set -g visual-activity off
      setw -g monitor-activity off
      setw -g monitor-bell off
      set -g history-limit 10000

      set-option -g renumber-windows on
      set -g base-index 1
      setw -g pane-base-index 1

      bind r source-file ~/.config/tmux/tmux.conf \; display '~/.config/tmux/tmux.conf sourced'
      bind > swap-pane -D
      bind < swap-pane -U
      bind | swap-pane

      bind -r H resize-pane -L 5
      bind -r J resize-pane -D 5
      bind -r K resize-pane -U 5
      bind -r L resize-pane -R 5
    '';
  };

  xdg.configFile = {
    hvim.source = inputs.hvim.outPath;
  };

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };

  programs.nh = {
    enable = true;
    clean.enable = false;
    clean.extraArgs = "--keep-since 4d --keep 3";
    flake = "/home/hank/.config/nix-config";
  };

}
