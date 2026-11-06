{
  config,
  pkgs,
  ...
}: let
  package = pkgs.callPackage ../../../pkgs/safari-mru {};
  log = "${config.home.homeDirectory}/Library/Logs/safari-mru.log";
in {
  home.packages = [package];

  # Permission setup and the scope of tab history: docs/safari-mru.md.
  launchd.agents.safari-mru = {
    enable = true;
    config = {
      ProgramArguments = ["${package}/bin/safari-mru"];
      RunAtLoad = true;
      KeepAlive = true;
      ThrottleInterval = 30;
      ProcessType = "Interactive";
      StandardOutPath = log;
      StandardErrorPath = log;
    };
  };
}
