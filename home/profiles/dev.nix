{ pkgs, lib, ... }:
{
  imports = [
    ../modules/vim
    ../modules/helix
  ];

  home.packages = with pkgs; [
    # neovim dependencies
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
    # gcc

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
    yazi
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
  ];
  programs.zsh = {
    enable = true;
    # dotDir = ".config/zsh";
  };
  programs.direnv = {
    enable = true;
    enableZshIntegration = true;
    enableBashIntegration = true;
    nix-direnv.enable = true;
  };
}
