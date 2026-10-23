{config, ...}: let
  m = config.flake.modules;
in {
  hosts.aarch64-headless = {
    system = "aarch64-linux";
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
