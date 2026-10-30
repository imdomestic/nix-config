{
  config,
  pkgs,
  ...
}: let
  socket = "${config.home.homeDirectory}/Library/Application Support/rex/server.sock";
  log = "${config.home.homeDirectory}/Library/Logs/rex-tailnet-relay.log";
  start = pkgs.writeShellScript "rex-tailnet-relay" ''
    set -eu
    address=$(/Applications/Tailscale.app/Contents/MacOS/Tailscale ip -4)
    test -n "$address"
    exec ${pkgs.socat}/bin/socat \
      "TCP4-LISTEN:7297,bind=$address,reuseaddr,fork,range=100.64.0.0/10" \
      "UNIX-CONNECT:${socket}"
  '';
in {
  # Every reachable tailnet node gets Rex's local-user access; docs/rex.md#tailnet-access.
  launchd.agents.rex-tailnet-relay = {
    enable = true;
    config = {
      ProgramArguments = ["${start}"];
      RunAtLoad = true;
      KeepAlive = true;
      ThrottleInterval = 30;
      StandardOutPath = log;
      StandardErrorPath = log;
    };
  };
}
