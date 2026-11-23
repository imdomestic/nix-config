# Per-user applications; the desktop role provides the system Flatpak service.
{
  inputs,
  lib,
  pkgs,
  ...
}: {
  imports = [inputs.nix-flatpak.homeManagerModules.nix-flatpak];

  services.flatpak = {
    enable = true;
    remotes = [
      {
        name = "flathub";
        location = "https://dl.flathub.org/repo/flathub.flatpakrepo";
      }
    ];
    uninstallUnmanaged = false;
    packages = [
      "com.google.Chrome"
      "com.qq.QQ"
      "com.spotify.Client"
      "org.prismlauncher.PrismLauncher"
      "org.pwmt.zathura"
      "com.github.ahrm.sioyek"
      "org.upscayl.Upscayl"
    ];
    update = {
      onActivation = true;
      auto = {
        enable = true;
        onCalendar = "daily";
      };
    };
  };

  # Keep the existing encore Chinese locale support when applications move sandboxes.
  home.activation.flatpak-languages = lib.hm.dag.entryBefore ["flatpak-managed-install"] ''
    if [ "$(${lib.getExe pkgs.flatpak} config --user --get languages 2>/dev/null || true)" != "en;zh" ]; then
      $DRY_RUN_CMD ${lib.getExe pkgs.flatpak} config --user --set languages "en;zh" || true
      $DRY_RUN_CMD ${lib.getExe pkgs.flatpak} --user --noninteractive update || true
    fi
  '';
}
