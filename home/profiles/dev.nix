{
  pkgs,
  pkgs-unstable,
  lib,
  ...
}: {
  imports = [
    ../modules/vim
    ../modules/helix
  ];

  home.packages = with pkgs; [
    # neovim dependencies
    devenv
    codesnap
    lua51Packages.lua
    lua51Packages.luarocks
    ruff
    basedpyright
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
    nodejs_22
    sqlite
    sqlite-interactive
    tree-sitter
    imagemagick
    fd
    mermaid-cli
    tectonic
    # texliveTeTeX

    wasmtime
    git-filter-repo
    duckdb
    tree-sitter
    pgcli
    usql
    gnumake
    gh
    zellij
    gcc
    elan
    lazygit

    # utils
    hyperfine
    xh
    fselect
    rusty-man
    delta
    tokei
    mprocs

    pandoc
    yq-go
    jq
    posting
    tldr
    jujutsu
    deploy-rs

    # networking
    mtr
    dnsutils
    ldns
    aria2
    socat
    nmap
    ipcalc

    #misc
    cowsay
    gnused
    gnutar
    gawk
    gnupg

    # devops
    nerdctl
    kubectl
    k9s
    kubernetes-helm

    # agents
    pkgs-unstable.codex
    pkgs-unstable.gemini-cli
    pkgs-unstable.opencode
  ];

  programs.direnv = {
    enable = true;
    enableZshIntegration = true;
    enableBashIntegration = true;
    nix-direnv.enable = true;
  };
}
