{
  pkgs,
  lib,
  ...
}: {
  imports = [
    ../modules/vim
    ../modules/helix
  ];

  home.packages = with pkgs; [
    # neovim dependencies
    codesnap
    nerdctl
    kubectl
    k9s
    kubernetes-helm
    zoxide
    lua51Packages.lua
    lua51Packages.luarocks
    ruff
    uv
    basedpyright
    wget
    curl
    typst
    tinymist
    taplo
    yaml-language-server
    typescript-language-server
    vue-language-server
    vtsls
    astro-language-server
    tailwindcss-language-server
    vscode-langservers-extracted
    typstyle
    marksman
    markdownlint-cli
    prettierd
    lua-language-server
    bash-language-server
    nil
    alejandra
    neovide
    nodejs_22
    # sqlite
    # sqlite-interactive
    tree-sitter
    imagemagick
    fd
    mermaid-cli
    tectonic
    # texliveTeTeX
    wasmtime
    gemini-cli
    codex
    git-filter-repo
    duckdb
    # pgloader
    pgcli
    usql
    gnumake
    gh
    zellij
    gcc
    lazygit
    elan

    # utils
    hyperfine
    xh
    fselect
    rusty-man
    delta
    ripgrep-all
    tokei
    mprocs
    wireguard-tools

    pandoc
    fastfetch
    neofetch
    ripgrep
    jq
    yq-go
    eza
    fzf
    duf
    btop
    tldr
    tmux
    posting
    just
    bat

    jujutsu
    deploy-rs

    # archives
    zip
    xz
    unzip
    p7zip

    # networking
    mtr
    iperf3
    dnsutils
    ldns
    aria2
    socat
    nmap
    ipcalc

    #misc
    cowsay
    file
    which
    tree
    gnused
    gnutar
    gawk
    zstd
    gnupg
    tree-sitter
    zinit

    # qol
    comma
    nix-output-monitor
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

      bind r source-file ~/.config/tmux/tmux.conf \; display '~/.config/tmux/tmux.conf sourced'
    '';
  };
  programs.direnv = {
    enable = true;
    enableZshIntegration = true;
    enableBashIntegration = true;
    nix-direnv.enable = true;
  };
}
