{
  wsl = {
    enable = true;
    defaultUser = "fendada";
  };

  time.timeZone = "Asia/Shanghai";
  security.sudo.wheelNeedsPassword = false;
  programs.zsh.enable = true;

  # systemd 后台任务不会继承 WSL autoProxy 注入到交互终端的环境变量。
  systemd.services.home-sync.environment = {
    http_proxy = "http://127.0.0.1:7897";
    https_proxy = "http://127.0.0.1:7897";
    no_proxy = "localhost,127.0.0.1,::1,.inner.imdomestic.com";
  };

  system.stateVersion = "26.05";
}
