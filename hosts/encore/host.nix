{inputs, ...}: {
  hosts.encore = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["server" "gpu-compute" "desktop" "gui"];
    tsName = "encore.inner.imdomestic.com";
    ageKey = "age1f6suumsw5f3e5sqf46j63kmympqk0anexjvuwsg7uh02wxnkwymqmkj32v";

    modules = [
      ../../system/modules/sudo-pwfeedback.nix
      ./cooling.nix
      ./keyboard.nix
      ./retained-services.nix
      ../../system/modules/linwhite-smb/nixos.nix
      ../../system/modules/vex
      ./vex.nix
    ];

    externalModules = [
      inputs.nixos-hardware.nixosModules.asus-zephyrus-gu603h
      inputs.nix-index-database.nixosModules.default
    ];

    users = {
      hank.ageKey = "age1wh7zpq8aaqx5anad9nxk9cr40q0rq2qcnsrpujmrmsf8z59aycsqhlpmth";
      linwhite.ageKey = "age1kmgn6snvphehfluadsztazkvlj5q8u6rydzm3at0y3muu45ny43szct0qr";
    };
  };
}
