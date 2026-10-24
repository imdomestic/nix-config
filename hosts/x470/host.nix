{inputs, ...}: {
  hosts.x470 = {
    system = "x86_64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["desktop" "gui" "server"];
    ip = "10.0.0.77";
    sshUser = "root";

    modules = [
      ./system.nix
      ./hardware-configuration.nix
    ];

    externalModules = [
      inputs.nix-minecraft.nixosModules.minecraft-servers
    ];

    users.hank = {};
  };
}
