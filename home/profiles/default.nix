{
  core = ./core.nix;
  dev = ./dev.nix;
  gui = {
    linux = ./gui/linux.nix;
    darwin = ./gui/darwin.nix;
  };
}
