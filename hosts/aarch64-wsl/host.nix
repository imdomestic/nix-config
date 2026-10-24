{inputs, ...}: {
  hosts.aarch64-wsl = {
    system = "aarch64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["server"];

    externalModules = [
      inputs.nixos-wsl.nixosModules.default
      inputs.nix-index-database.nixosModules.default
      inputs.sops-nix.nixosModules.sops
    ];

    users.hank = {};
  };
}
