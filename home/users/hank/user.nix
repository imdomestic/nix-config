{config, ...}: let
  hm = config.flake.modules.homeManager;
in {
  flake.modules.homeManager = {
    hank = ./default.nix;
    # 共享工具链 + 打开 nixvim 的 dev 插件;没有 dev 的机器由 default.nix 提供
    # 精简版 nixvim(保留 nix 支持)。
    hank-dev = ./dev.nix;
    hank-gnome = ./gnome.nix;
    hank-flatpak = ./flatpak.nix;
  };

  users.hank = {
    tier = "dev";
    module = hm.hank;
    dev = hm.hank-dev;
    gui = {
      linux.modules = [hm.hank-gnome hm.ibus];
      darwin.profile = hm.gui-darwin;
    };
  };
}
