{
  core = ./core.nix;
  # dev 不再是共享 profile,改为按用户:见 home/users/<user>/dev.nix
  # (各自 import 本目录的 dev.nix 复用共享工具链 + 自己的 nixvim)
  base = ./base.nix;
  gui = {
    linux = ./gui/linux.nix;
    darwin = ./gui/darwin.nix;
  };
}
