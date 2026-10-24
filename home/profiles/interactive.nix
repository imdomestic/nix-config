{pkgs, ...}: {
  home.packages = with pkgs; [
    bat
    fastfetch
    eza
    duf
    btop
  ];

  # 只负责打开;默认参数是各人的偏好,在 home/users/<account>/modules/。
  programs.fzf.enable = true;

  programs.zoxide = {
    enable = true;
    enableNushellIntegration = true;
  };
}
