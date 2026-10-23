{config, ...}: let
  hm = config.flake.modules.homeManager;
in {
  flake.modules.homeManager = {
    kenneth = ./default.nix;
    # Alex 上原来那台 Mac 的 Homebrew 软件和 shell 钩子。
    kenneth-alex = ./alex.nix;
  };

  users.kenneth = {
    module = hm.kenneth;
    gui.darwin.profile = hm.gui-darwin;
  };
}
