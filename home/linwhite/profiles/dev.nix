{...}: {
  # linwhite 的 dev profile:共享工具链 + 打开 nixvim 的 dev 插件。
  # 账户到 dev 档时由 flake/builders/homes.nix 加载(见 ../user.nix);
  # 没有 dev 的机器由 linwhite/default.nix 提供精简版 nixvim(保留 nix 支持)。
  imports = [
    ../modules/dev-tools.nix
    ../modules/nixvim
    ../modules/opencode
    ../modules/flat-white/opencode.nix
    ../modules/codex
    ../modules/flat-white/codex.nix
    ../modules/claude-code.nix
    ../modules/flat-white/pi.nix
    ../modules/flat-white/delta.nix
    ../modules/flat-white/lazygit.nix
    ../modules/flat-white/k9s.nix
  ];

  my.nixvim.dev.enable = true;

  programs.delta = {
    enable = true;
    enableGitIntegration = true;
  };
  programs.lazygit = {
    enable = true;
    enableZshIntegration = false;
  };
  programs.k9s.enable = true;

  programs.claude-code = {
    enable = true;
    package = null;
  };
}
