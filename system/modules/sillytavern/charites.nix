{
  config,
  lib,
  pkgs,
  ...
}: let
  source = pkgs.fetchFromGitHub {
    owner = "SenriYuki";
    repo = "SillyTavern-Charites";
    rev = "672770d102d7069cea98f8178dc763a6fcdf5305";
    hash = "sha256-MdORjHhPwlopCtWkraufSx1SCDtwc6De5IXt01rQ48k=";
  };
  target = "/var/lib/SillyTavern/extensions/SillyTavern-Charites";
in {
  # The extension hardcodes this directory name; its settings stay in ST's user data.
  systemd.services.sillytavern = {
    restartTriggers = [source];
    preStart = lib.mkAfter ''
      if [ -e ${target} ] && [ ! -L ${target} ]; then
        echo "Refusing to replace an unmanaged Charites installation" >&2
        exit 1
      fi
      ${pkgs.coreutils}/bin/ln -sfn ${source} ${target}
    '';
  };
  assertions = [
    {
      assertion = config.services.sillytavern.enable;
      message = "Charites requires SillyTavern.";
    }
  ];
}
