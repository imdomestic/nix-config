{
  hosts.gpd = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["desktop" "gui"];

    modules = [
      ../../system/modules/sudo-pwfeedback.nix
    ];

    users.linwhite = {};
  };
}
