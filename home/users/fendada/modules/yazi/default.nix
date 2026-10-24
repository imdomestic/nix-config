# yazi 的偏好。原来在 home/profiles/interactive.nix 里给所有人;那里现在只在
# interactive 档以上打开 programs.yazi,档位不到时这些设置不起作用。
{
  programs.yazi = {
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
