# yazi:interactive 档以上才装,主题在 ../flat-white/yazi.nix。
{
  config,
  lib,
  ...
}: {
  programs.yazi = {
    enable = lib.elem config.my.home.tier ["interactive" "dev"];
    shellWrapperName = "y";
    settings.theme.flavor = {
      dark = "kanso-ink";
      light = "kanso-pearl";
    };
    flavors = {
      kanso-ink = ./kanso-ink.yazi;
      kanso-pearl = ./kanso-pearl.yazi;
    };
  };
}
