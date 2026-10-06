{
  config,
  lib,
  pkgs,
  ...
}: let
  netfs = pkgs.callPackage ../../pkgs/pyobjc-framework-netfs {};
  python = pkgs.python3.withPackages (ps: [ps.pyobjc-framework-Security netfs]);
  home = config.users.users.linwhite.home;
in {
  assertions = [{
    assertion = config.system.primaryUser == "linwhite";
    message = "linwhite 的 SMB 挂载需要 linwhite 用户 LaunchAgent。";
  }];
  launchd.user.agents = lib.genAttrs ["seraph" "encore"] (host: {
    serviceConfig = {
      Label = "org.nixos.linwhite-smb-${host}";
      ProgramArguments = [
        "${python}/bin/python3"
        "${../../scripts/mount-linwhite-smb.py}"
        "--server"
        host
        "--share"
        "${host}-linwhite"
        "--shortcut"
        "${home}/Servers/${host}"
      ];
      RunAtLoad = true;
      StartInterval = 60;
      ProcessType = "Background";
      LimitLoadToSessionType = "Aqua";
      StandardOutPath = "${home}/Library/Logs/linwhite-smb-${host}.log";
      StandardErrorPath = "${home}/Library/Logs/linwhite-smb-${host}.log";
    };
  });
}
