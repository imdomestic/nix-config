{
  config,
  lib,
  pkgs,
  ...
}: let
  python = pkgs.python3.withPackages (ps: [ps.tomlkit]);
in {
  programs.codex = {
    enable = true;
    # Codex 的包由共享 dev profile 提供。
    package = null;
    settings.tui = {
      status_line = [
        "current-dir"
        "git-branch"
        "model-with-reasoning"
        "permissions"
        "context-used"
        "weekly-limit"
      ];
    };
  };

  # 用原生模块生成配置片段,激活时合并;Codex 仍可写回其余运行时设置。
  home.file.".codex/config.toml".enable = false;
  home.activation.codexSettings = lib.hm.dag.entryAfter ["writeBoundary"] ''
    run ${python}/bin/python ${./merge-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.codex/config.toml"} \
      ${config.home.file.".codex/config.toml".source}
  '';

  # tmTheme 是语法高亮资源;当前 HM 的 Codex 模块没有 themes 选项。
  home.file.".codex/themes/evergarden-winter.tmTheme".source = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/evergardentheme/bat/aa5b92e927d1169673050f4f444496590e053487/themes/evergarden-winter.tmTheme";
    hash = "sha256-jZ6Rc6ScIffy73FQJn8FYqJG5pS/6plk4oqJModbxKw=";
  };
  home.file.".codex/themes/kanso-zen.tmTheme".source = import ./kanso-zen.nix {inherit pkgs;};
}
