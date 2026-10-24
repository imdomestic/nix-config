# hank 在 praxic 上的东西。
{pkgs, ...}: {
  imports = [
    ./modules/postgresql
    ./modules/tailscale
  ];

  my.vscode.enable = true;

  # 用来推别的机器,不是这台 Mac 自己要的。
  home.packages = with pkgs; [
    nixos-rebuild
    nixos-rebuild-ng
  ];
}
