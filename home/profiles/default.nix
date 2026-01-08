{
  core = ./core.nix;
  dev = ./dev.nix;
  base = ./base.nix;
  gui = {
    linux = ./gui/linux.nix;
    darwin = ./gui/darwin.nix;
  };
}
