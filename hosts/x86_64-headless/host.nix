{
  hosts.x86_64-headless = {
    system = "x86_64-linux";
    kind = "home";
    inChina = true;
    roles = ["server"];

    systemManager = {
      enable = true;
      modules = [
        ../../system/modules/nix-settings.nix
        ./system-manager.nix
      ];
    };

    users.hank = {};
  };
}
