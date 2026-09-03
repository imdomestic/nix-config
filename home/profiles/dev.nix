{
  pkgs,
  pkgs-unstable,
  inputs,
  lib,
  system,
  ...
}: {
  # 用户无关的共享 dev 工具链(LSP / CLI / direnv)。
  # 编辑器(nixvim)是按用户的,放在各自的 home/users/<user>/dev.nix 里,
  # 由那里 import 本文件复用这套工具链。
  home.packages = with pkgs;
    [
      # neovim dependencies
      pkgs-unstable.devenv
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
      nodejs_22
      # sqlite
      # sqlite-interactive
      imagemagick
      ghostscript
      fd
      mermaid-cli
      tectonic
      resvg
      # texliveTeTeX

      cachix

      wasmtime
      git-filter-repo
      duckdb
      tree-sitter
      pgcli
      usql
      gnumake
      gh
      elan
      rustup
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
      tshark

      #misc
      cowsay
      gnused
      gnutar
      gawk
      gnupg

      # devops
      kubectl
      k9s
      kubernetes-helm

      # android
      android-tools

      # agents
      inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.claude-code
      inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.codex
      inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.opencode
      inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.pi
    ]
    ++ lib.optionals (lib.hasInfix "linux" system) [
      iproute2
      nerdctl
      multipath-tools
      bubblewrap

      # C / 内核构建。原本在 b650 / gpd / m16 / tank 四台的
      # environment.systemPackages 里各抄一份 —— 编译是人干的活,不是机器要的。
      # 只给 linux:elfutils / libelf 在 darwin 上是 unsupported,放外面会让
      # 两台 Mac 的 home 直接求值失败。
      gcc
      pkg-config
      flex
      bison
      elfutils
      libelf
    ]
    ++ lib.optionals (lib.hasInfix "darwin" system) [
      iproute2mac
    ];

  programs.direnv = {
    enable = true;
    enableZshIntegration = true;
    enableBashIntegration = true;
    nix-direnv.enable = true;
    enableNushellIntegration = true;
  };

  # TODO: update to 26.05
  # programs.claude-code = {
  #   enable = true;
  #   enableMcpIntegration = true;
  #   package = pkgs-unstable.claude-code;
  # };
}
