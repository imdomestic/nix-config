# hank 在 tank 上的东西。这台没有 gui role,桌面工具单独列出。
{pkgs, ...}: {
  home.packages = with pkgs; [
    brightnessctl
    radeontop
    clapper
  ];
}
