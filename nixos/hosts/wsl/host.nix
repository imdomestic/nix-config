{inputs, ...}: {
  hosts.wsl = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = [];

    modules = [
      ./system.nix
    ];

    externalModules = [
      inputs.nixos-wsl.nixosModules.wsl
      inputs.nix-index-database.nixosModules.default
    ];

    users.hank.ageKey = "age1zrnfrlp7ps4e9c5hpefz4g7fycsqf6ntswftmcj6dzlpyx6e9essx2vrj5";
  };
}
