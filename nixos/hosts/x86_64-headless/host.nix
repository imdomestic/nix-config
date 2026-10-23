{config, ...}: let
  m = config.flake.modules;
in {
  hosts.x86_64-headless = {
    system = "x86_64-linux";
    kind = "home";
    roles = ["server"];

    systemManager = {
      enable = true;
      modules = [
        m.systemManager.nix-settings
        ./system-manager.nix
      ];
    };

    users.hank = {
      tier = "minimal";
      modules = [m.homeManager.hank-dev];
    };
  };
}
