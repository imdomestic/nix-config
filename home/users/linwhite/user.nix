{config, ...}: let
  hm = config.flake.modules.homeManager;
in {
  flake.modules.homeManager = {
    linwhite = ./default.nix;
    # 共享工具链 + 打开 nixvim 的 dev 插件;没有 dev 的机器由 default.nix 提供
    # 精简版 nixvim(保留 nix 支持)。
    linwhite-dev = ./dev.nix;
    linwhite-aerospace = ./aerospace.nix;
    # 只在某一台上加载的部分,由那台 host.nix 的 users.linwhite.modules 引用。
    linwhite-aegis = ./hosts/aegis.nix;
    linwhite-encore = ./hosts/encore.nix;
    linwhite-gpd = ./hosts/gpd.nix;
    linwhite-seraph = ./hosts/seraph.nix;
  };

  users.linwhite = {
    tier = "dev";
    module = hm.linwhite;
    dev = hm.linwhite-dev;
    ageKeys.personal = "age1guuksgwc7ldf0r99dq49kfaw5xkw59rmtlwpyc8yzz3lu5lzwvxq65s6g7"; # linwhite@linwhite.top
    gui = {
      linux.profile = hm.gui-linux;
      darwin = {
        profile = hm.gui-darwin;
        modules = [hm.linwhite-aerospace];
      };
    };
  };
}
