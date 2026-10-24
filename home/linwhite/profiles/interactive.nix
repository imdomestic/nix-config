# interactive 档以上加载。
{pkgs, ...}: {
  home.packages = with pkgs; [
    bat
    fastfetch
    eza
    duf
    btop
  ];

  # 默认参数在 ../modules/fzf.nix。
  programs.fzf.enable = true;

  programs.zoxide = {
    enable = true;
    enableNushellIntegration = true;
  };
}
