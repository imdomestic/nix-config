{
  inputs,
  lib,
  pkgs-unstable,
  ...
}: {
  # linwhite 的 dev profile:共享工具链 + linwhite 自己的 nixvim。
  # host 只需把 userModules.linwhite.dev 加进该用户的 home.modules 即可按需开启。
  imports = [
    inputs.nixvim.homeModules.nixvim
    ../../profiles/dev.nix
    ../../modules/nixvim/linwhite
  ];

  programs.neovim = {
    enable = lib.mkForce false;
    package = pkgs-unstable.neovim-unwrapped;
  };
}
