# interactive 档以上加载。
{
  inputs,
  pkgs,
  ...
}: {
  home.packages = with pkgs; [
    bat
    fastfetch
    eza
    duf
    btop
    inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.claude-code
  ];

  # 默认参数在 ../modules/fzf.nix。
  programs.fzf.enable = true;

  programs.zoxide = {
    enable = true;
    enableNushellIntegration = true;
  };
}
