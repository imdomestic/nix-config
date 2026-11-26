{inputs, ...}: {
  hosts."7945hx-wsl" = {
    system = "x86_64-linux";
    kind = "nixos";
    inChina = true;
    roles = [];

    # WSL 不使用 server 角色，单独启用 home-sync。
    modules = [../../system/modules/home-sync.nix];
    externalModules = [inputs.nixos-wsl.nixosModules.default];

    users.fendada = {
      tier = "dev";
      ageKey = "age1u9pju64c3uf67hg6huhz38a9mupv7au6egzg5uv5mtcxdpn42u6qa7lz8h";
    };
  };
}
