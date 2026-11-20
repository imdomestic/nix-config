{inputs, ...}: {
  hosts.x470 = {
    system = "x86_64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["desktop" "gui" "server"];
    sshUser = "root";

    externalModules = [
      inputs.nix-minecraft.nixosModules.minecraft-servers
    ];

    users.hank = {};
  };
}
