{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts."268v" = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["desktop" "gui"];
    # tsName = "268v.inner.imdomestic.com";

    modules = [
      ./system.nix
      ./hardware-configuration.nix
      ./desktop.nix
      ./display.nix
      ./virtualisation.nix
    ];
    hardwareModules = [inputs.nixos-hardware.nixosModules.lenovo-yoga-7-14ILL10];
    externalModules = [
      inputs.NixVirt.nixosModules.default
      inputs.nix-index-database.nixosModules.default
      inputs.wayland-scroll-factor.nixosModules.default
    ];

    # 和别处的 GNOME 一样,外加 flatpak。
    users.hank = {
      gui.modules = with m.homeManager; [hank-gnome hank-flatpak ibus];
      ageKey = "age199f3re3sturx83zkmedc5qkz7aqra656w6cz9zttkcxg0slndudqlf8sca";
    };
  };
}
