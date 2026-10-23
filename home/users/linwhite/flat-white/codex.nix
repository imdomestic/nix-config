{
  config,
  lib,
  pkgs,
  ...
}: {
  config = lib.mkIf config.programs.codex.enable {
    programs.codex.settings.tui.theme = "flat-white";
    # tmTheme 是主题资源；配置合并由 codex/default.nix 负责。
    home.file.".codex/themes/flat-white.tmTheme".source = import ./tmtheme.nix {inherit pkgs;};
  };
}
