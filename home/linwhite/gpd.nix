# linwhite 在 gpd 上的东西:当桌面用的应用。原本躺在 environment.systemPackages 里 ——
# 它们是人看的、人点的,机器自己一个都不需要,却要 root + 整机重建才能改。
{pkgs, ...}: {
  home.packages = with pkgs; [
    firefox
    clapper
    # GPU 占用率、调频与带 ROCm 的 btop。
    radeontop
    corectrl
    btop-rocm
  ];
}
