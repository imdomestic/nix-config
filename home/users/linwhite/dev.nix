{
  config,
  lib,
  ...
}: {
  # linwhite 的 dev profile:共享工具链 + 打开 nixvim 的 dev 插件。
  # 账户到 dev 档时由 flake/builders/homes.nix 加载(见 ./user.nix);
  # 没有 dev 的机器由 linwhite/default.nix 提供精简版 nixvim(保留 nix 支持)。
  imports = [
    ../../profiles/dev.nix
    ./nixvim
    ../../modules/opencode
    ./flat-white/opencode.nix
    ../../modules/codex
    ./flat-white/codex.nix
    ./claude-code.nix
    ./flat-white/pi.nix
    ./flat-white/delta.nix
    ./flat-white/lazygit.nix
    ./flat-white/k9s.nix
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
    settings = lib.mkIf (config.my.host.name == "aegis") {
      env = {
        # macOS 上仅使用 system 时，当前运行时读取的 CA 无法验证 Anthropic 证书。
        CLAUDE_CODE_CERT_STORE = "bundled,system";
        CLAUDE_CODE_SUBAGENT_MODEL = "haiku";
        CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS = "8";
      };
      model = "opus";
      statusLine = {
        type = "command";
        command = "sh ${config.home.homeDirectory}/.claude/statusline-command.sh";
      };
      modelSettings.claude-opus-5-5.effortLevel = "xhigh";
      skipDangerousModePermissionPrompt = true;
      enabledPlugins."swift-lsp@claude-plugins-official" = true;
    };
  };
}
