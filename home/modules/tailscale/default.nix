{config, ...}: {
  launchd.agents.tailscale-autoconnect = {
    enable = true;
    config = {
      ProgramArguments = [
        "/Applications/Tailscale.app/Contents/MacOS/tailscale"
        "up"
        "--hostname=${config.my.host.name}"
        "--login-server=https://tailscale.imdomestic.com:8443"
        "--timeout=45s"
      ];
      RunAtLoad = true;
      KeepAlive.SuccessfulExit = false;
      ThrottleInterval = 30;
      StandardOutPath = "${config.home.homeDirectory}/Library/Logs/tailscale-autoconnect.log";
      StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/tailscale-autoconnect.log";
    };
  };
}
