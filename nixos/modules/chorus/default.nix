{...}: {
  imports = [
    ./controller.nix
    ./k3s-server.nix
    ./metrics-server.nix
    ./legacy-minecraft.nix
  ];

  services.chorusd.enable = true;
}
