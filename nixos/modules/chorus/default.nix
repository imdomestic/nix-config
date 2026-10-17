{...}: {
  imports = [
    ./controller.nix
    ./k3s-server.nix
    ./metrics-server.nix
  ];

  services.chorusd.enable = true;
}
