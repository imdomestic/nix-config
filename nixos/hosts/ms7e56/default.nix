{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["desktop" "gui"];
  tsName = "ms7e56.inner.imdomestic.com";

  profiles = with nixosProfiles; [base desktop];
  modules = [./system.nix ./hardware-configuration.nix];
  externalModules = [inputs.nix-index-database.nixosModules.default];
  homeOverlays = [
    (final: prev: {
      qq = prev.qq.overrideAttrs {
        src = final.fetchurl {
          url = "https://github.com/Rodert/qq-versions/releases/download/qq-packages-20260528-3e8913a2/QQ_3.2.29_260528_amd64_01.deb";
          hash = "sha256-HjgoB5ZzyUmUvA9HgNXYUoZHY5kgZZhi1J0cLyoZjiU=";
        };
      };
    })
  ];

  users.linwhite.home = {
    profiles = with homeProfiles; [core base interactive gui.linux];
    modules = [userModules.linwhite.module userModules.linwhite.dev];
  };
}
