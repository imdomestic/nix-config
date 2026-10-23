{config, ...}: let
  m = config.flake.modules;
in {
  hosts.marble = {
    system = "aarch64-linux";
    kind = "nixos";
    roles = ["server"];
    sshUser = "hank";
    # tsName = "marble.inner.imdomestic.com";

    profiles = with m.nixos; [
      base
      server
    ];

    modules = [
      ./system.nix
    ];

    users.hank = {
      extraGroups = ["wheel"];
      nixos = {
        linger = true;
        openssh.authorizedKeys.keys = [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILUdWAJA+GYaOtVHVkrvrEpwGpK//0hYdAYjYq/rzvtn ysh2291939848@outlook.com"
        ];
      };
    };
  };
}
