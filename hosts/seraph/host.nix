{inputs, ...}: {
  hosts.seraph = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["server"];
    tsName = "seraph.inner.imdomestic.com";
    ageKey = "age12z6tru33ag256gs62fufpjkxnjta3mjn5ryv6uvqaukre7yx4g7q37am5f";

    modules = [
      ../../system/modules/sudo-pwfeedback.nix
      ./compute.nix
      ./vex-agent.nix
      ../../system/modules/linwhite-smb/nixos.nix
      ../../system/modules/bonsai-conversion.nix
      ../../system/modules/bonsai-ninfer.nix
      ../../system/modules/bonsai-tailnet.nix
      {
        services.bonsaiNinfer.enable = true;
        services.bonsaiNinfer.tailnet.enable = true;
      }
    ];
    externalModules = [inputs.nix-index-database.nixosModules.default];

    users.linwhite.ageKey = "age1svatkwy2klm39twkpv7rxfteampuzkyu3ccxtjzpmuz2kq3d6sus8l3hg4";
  };
}
