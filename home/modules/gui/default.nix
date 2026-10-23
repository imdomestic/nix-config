{
  pkgs,
  lib,
  config,
  ...
}: let
  host = config.my.host.name;
  # 引了 gui.linux 的机器里,这几台作为桌面使用。下面这组包原本躺在
  # 各自的 environment.systemPackages 里 —— 它们是人看的、人点的,机器自己一个
  # 都不需要,却要 root + 整机重建才能改。
  #
  # 只有引了 gui.linux 的 home 才到得了这里。taipan、encore、tank 的 hank 走的是
  # gnome.nix,不经过这个模块;tank 那几个桌面包挂在 home/users/hank/default.nix
  # 的 host 条件里。
  desktopWorkstations = ["gpd"];
in {
  home.packages = with pkgs;
    lib.optionals (builtins.elem host desktopWorkstations) [
      firefox
      clapper
      # GPU 占用率、调频与带 ROCm 的 btop。
      radeontop
      corectrl
      btop-rocm
    ];
}
