{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server"];
  tsName = "ms7e56.inner.imdomestic.com";

  profiles = with nixosProfiles; [base];
  modules = [
    ./system.nix
    ./hardware-configuration.nix
    ./compute.nix
    ../../modules/bonsai-conversion.nix
    ../../modules/bonsai-ninfer.nix
    ../../modules/bonsai-tailnet.nix
    {
      services.bonsaiNinfer.enable = true;
      services.bonsaiNinfer.tailnet.enable = true;
    }
  ];
  externalModules = [inputs.nix-index-database.nixosModules.default];
  users.linwhite.home = {
    profiles = with homeProfiles; [core base interactive];
    modules = [
      ./home.nix
      userModules.linwhite.module
      userModules.linwhite.dev
      ../../../home/modules/opencode/local-bonsai.nix
    ];
  };
}
