{config, ...}: let
  m = config.flake.modules;
in {
  hosts.hackintosh = {
    system = "x86_64-darwin";
    kind = "darwin";
    roles = ["desktop" "gui"];

    profiles = [m.darwin.base];

    modules = [
      ./system.nix
    ];

    users.hank.tier = "interactive";
  };
}
