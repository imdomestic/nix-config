{inputs, ...}: {
  hosts.alex = {
    system = "aarch64-darwin";
    kind = "darwin";
    inChina = true;
    roles = ["desktop" "gui"];

    externalModules = [
      inputs.nix-index-database.darwinModules.nix-index
      inputs.determinate.darwinModules.default
    ];

    users.kenneth = {};
  };
}
