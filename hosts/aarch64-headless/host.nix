{
  hosts.aarch64-headless = {
    system = "aarch64-linux";
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
