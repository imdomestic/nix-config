{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.lidguard;
in {
  options.services.lidguard = {
    enable = lib.mkEnableOption "lidguard lid-triggered sleep management";

    graceSeconds = lib.mkOption {
      type = lib.types.int;
      default = 1800;
      description = "Seconds to wait before sleeping with the lid closed on AC power.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix {};
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix {}";
      description = "The lidguard package to run.";
    };
  };

  config = lib.mkIf cfg.enable {
    launchd.daemons.lidguard.serviceConfig = {
      ProgramArguments = ["${cfg.package}/bin/lidguard"];
      UserName = "root";
      EnvironmentVariables.GRACE = toString cfg.graceSeconds;
      RunAtLoad = true;
      KeepAlive = true;
      StandardOutPath = "/var/log/lidguard.log";
      StandardErrorPath = "/var/log/lidguard.log";
    };
  };
}
