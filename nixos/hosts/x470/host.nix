{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.x470 = {
    system = "x86_64-linux";
    kind = "nixos";
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

    # 别处 hank 的 GNOME 用 gnome.nix + ibus,这台用的是共享的 gui.linux。
    users.hank.gui.profile = m.homeManager.gui-linux;
  };
}
