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
    devenv
    codesnap
    nerdctl
    kubectl
    k9s
    kubernetes-helm
    lua51Packages.lua
    lua51Packages.luarocks
    ruff
    uv
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
    neovide
    nil
    alejandra
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
    tree-sitter
  ];

  programs.direnv = {
    enable = true;
    enableZshIntegration = true;
    enableBashIntegration = true;
    nix-direnv.enable = true;
  };
}
