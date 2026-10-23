{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.seraph = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["server"];
    tsName = "seraph.inner.imdomestic.com";
    ageKey = "age12z6tru33ag256gs62fufpjkxnjta3mjn5ryv6uvqaukre7yx4g7q37am5f";

    profiles = [m.nixos.base];
    modules = [
      ./system.nix
      m.nixos.sudo-pwfeedback
      ./hardware-configuration.nix
      ./compute.nix
      ./vex-agent.nix
      m.nixos.linwhite-smb
      m.nixos.bonsai-conversion
      m.nixos.bonsai-ninfer
      m.nixos.bonsai-tailnet
      {
        services.bonsaiNinfer.enable = true;
        services.bonsaiNinfer.tailnet.enable = true;
      }
    ];
    externalModules = [inputs.nix-index-database.nixosModules.default];

    users.linwhite.ageKey = "age1svatkwy2klm39twkpv7rxfteampuzkyu3ccxtjzpmuz2kq3d6sus8l3hg4";
    users.linwhite.modules = [
      ./home.nix
      m.homeManager.opencode-local-bonsai
    ];
  };
}
