{inputs, ...}: {
  hosts."9950x" = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["gui"];

    modules = [
      ../../system/modules/sudo-pwfeedback.nix
    ];

    externalModules = [
      inputs.nixos-wsl.nixosModules.wsl
      inputs.nix-index-database.nixosModules.default
    ];

    users.linwhite = {};
  };
}
