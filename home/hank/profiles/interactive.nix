# interactive 档以上加载。
{pkgs, ...}: {
  home.packages = with pkgs; [
    bat
    # darwin 上的 fastfetch 把 rpath 指向 apple-sdk,一个人占约 480 MiB;
    # macchina 只要 ~2 MiB。fastfetch.minimal 也带着那条 rpath,不顶用。
    (
      if stdenv.hostPlatform.isDarwin
      then macchina
      else fastfetch
    )
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
