{inputs, ...}: {
  hosts."7945hx-wsl" = {
    system = "x86_64-linux";
    kind = "nixos";
    inChina = true;
    roles = [];

    externalModules = [inputs.nixos-wsl.nixosModules.default];

    users.fendada.tier = "dev";
  };
}
