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
    ageKeys.personal = "age18glzkfyda2qcs7ffqz9pgxrqc0p9e565xpcqxe85shdfltlv2ytq5rjp4v"; # 3526452465@qq.com
    gui.darwin.profile = hm.gui-darwin;
  };
}
