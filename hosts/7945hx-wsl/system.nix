{
  wsl = {
    enable = true;
    defaultUser = "fendada";
  };

  time.timeZone = "Asia/Shanghai";
  security.sudo.wheelNeedsPassword = false;
  programs.zsh.enable = true;

  system.stateVersion = "26.05";
}
