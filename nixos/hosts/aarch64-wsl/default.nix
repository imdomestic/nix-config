{inputs}: let
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "home";
  roles = ["server"];

  systemManager = {
    enable = true;
    modules = [
      ./system.nix
    ];
  };

  externalModules = [
    # inputs.daeuniverse.nixosModules.dae
    # inputs.daeuniverse.nixosModules.daed
    # inputs.niri.nixosModules.niri
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          dev
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
