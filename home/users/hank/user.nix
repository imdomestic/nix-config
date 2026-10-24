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
    hank-aerospace = ./aerospace.nix;
    hank-rex = ./rex.nix;
    # 只在某一台上加载的部分,由那台 host.nix 的 users.hank.modules 引用。
    hank-aarch64-wsl = ./hosts/aarch64-wsl.nix;
    hank-encore = ./hosts/encore.nix;
    hank-gizmo = ./hosts/gizmo.nix;
    hank-m1elite = ./hosts/m1elite.nix;
    hank-praxic = ./hosts/praxic.nix;
    hank-tank = ./hosts/tank.nix;
  };

  users.hank = {
    tier = "dev";
    module = hm.hank;
    dev = hm.hank-dev;
    # sops key 所在的机器不在 registry 里。
    ageKeys = {
      "1" = "age1zzwv2edh2ssz7xpmpcqr73rkh79j4mwjy50ap8dvm4c64ksmspxsz7mnat";
      "2" = "age175594x5r5ngze8rs5n2ga0976e0flh0xq2aqjq3xaldr28e703sqlcy9n6";
      "3" = "age1f0ch7vfsqs3u5c4mzqs4m228wge5vulz0s0yj30gkapk7nlk3g2s43x42l";
    };
    gui = {
      linux.modules = [hm.hank-gnome hm.hank-flatpak hm.ibus];
      darwin = {
        profile = hm.gui-darwin;
        modules = [hm.hank-aerospace hm.hank-rex];
      };
    };
  };
}
