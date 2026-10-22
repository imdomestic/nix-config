{
  config,
  lib,
  ...
}: {
  # linwhite 的 dev profile:共享工具链 + 打开 nixvim 的 dev 插件。
  # host 只需把 userModules.linwhite.dev 加进该用户的 home.modules 即可按需开启;
  # 没有 dev 的机器由 linwhite/default.nix 提供精简版 nixvim(保留 nix 支持)。
  imports = [
    ../../profiles/dev.nix
    ../../modules/nixvim/linwhite
    ../../modules/opencode
    ../../modules/opencode/flat-white.nix
    ../../modules/codex
    ../../modules/codex/flat-white.nix
    ../../modules/claude-code/linwhite.nix
    ../../modules/pi/flat-white.nix
    ../../modules/delta/flat-white.nix
    ../../modules/lazygit/flat-white.nix
    ../../modules/k9s/flat-white.nix
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
