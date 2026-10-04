{
  pkgs,
  inputs,
  lib,
  config,
  system,
  ...
}: let
  devenv = inputs.devenv.packages.${pkgs.stdenv.hostPlatform.system}.default;

  # codex 0.157 的 TUI 默认先起后台 app-server daemon,而 daemon 要求一个带
  # codex-package.json 的完整安装包,llm-agents 的包没有 —— 于是 `codex` 一启动
  # 就报 "this CLI has no complete local package"(`codex exec` 不受影响)。
  # 关掉 daemon_auto_start 就是 nixpkgs 的修法(NixOS/nixpkgs#567051),这里用
  # -c 覆盖,不必重编。用 makeWrapper 而不是 wrapProgram:真二进制不改名,
  # tmux 里看到的进程名还是 codex。
  # numtide/llm-agents.nix#9889 合并后删掉这层包装。
  codex = let
    upstream = inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.codex;
  in
    pkgs.symlinkJoin {
      name = "codex-${upstream.version}";
      paths = [upstream];
      nativeBuildInputs = [pkgs.makeWrapper];
      postBuild = ''
        rm $out/bin/codex
        makeWrapper ${upstream}/bin/codex $out/bin/codex \
          --add-flags "-c features.daemon_auto_start=false"
      '';
      inherit (upstream) meta;
    };
in {
  # 用户无关的共享 dev 工具链(LSP / CLI / direnv)。
  # 编辑器(nixvim)是按用户的,放在各自的 home/users/<user>/dev.nix 里,
  # 由那里 import 本文件复用这套工具链。
  home.packages = with pkgs;
    [
      # Nix configuration and deployment
      just
      nix-output-monitor
      sops
      nil
      alejandra

      # Network diagnostics and operations
      wireguard-tools
      iperf3

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
      vtsls
      tailwindcss-language-server
      vscode-langservers-extracted
      typstyle
      marksman
      markdownlint-cli
      prettierd
      biome
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
      codex
      inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.opencode
      inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.pi
      # inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.dsh
      # inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.hermes-agent
      # inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.hermes-desktop
    ]
    ++ lib.optionals (lib.hasInfix "linux" system) [
      iproute2
      nerdctl
      multipath-tools
      bubblewrap

      # C / 内核构建。原本在 taipan / gpd / encore / tank 四台的
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

  programs.nh = {
    enable = true;
    clean.enable = false;
    clean.extraArgs = "--keep-since 4d --keep 3";
    flake = "${config.home.homeDirectory}/.config/nix-config";
  };
}
