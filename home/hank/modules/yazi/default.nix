# hank 的 yazi。interactive 档以上才装:nixpkgs 的包装带着一串预览依赖,小机器犯不上。
{
  config,
  lib,
  ...
}: {
  programs.yazi = {
    enable = lib.elem config.my.home.tier ["interactive" "dev"];
    shellWrapperName = "y";
    # flavor 属于 theme.toml。原来写在 settings.theme 下,进的是 yazi.toml,yazi 不认,
    # kanso 一直没生效。
    theme.flavor = {
      dark = "kanso-ink";
      light = "kanso-pearl";
    };
    flavors = {
      kanso-ink = ./kanso-ink.yazi;
      kanso-pearl = ./kanso-pearl.yazi;
    };
  };
}
