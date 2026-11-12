# Flathub apps for linwhite, installed per user by nix-flatpak; the system side
# (services.flatpak) comes with the desktop role. The host file lists the apps.
{
  inputs,
  lib,
  pkgs,
  ...
}: {
  imports = [inputs.nix-flatpak.homeManagerModules.nix-flatpak];

  services.flatpak = {
    enable = true;
    update.auto = {
      enable = true;
      onCalendar = "weekly";
    };
  };

  # Flatpak 默认只根据宿主 LANG（en_US.UTF-8）下载语言包。为 Flatpak 显式启用中文支持，
  # 确保各 runtime / app 的 Locale 扩展（如 glibc locale、zh_CN 翻译）能够被下载，
  # 避免 Bambu Studio 等应用切换中文语言时因容器内缺失 zh_CN locale 而报错。
  home.activation.flatpak-languages = lib.hm.dag.entryBefore ["flatpak-managed-install"] ''
    if [ "$(${lib.getExe pkgs.flatpak} config --user --get languages 2>/dev/null || true)" != "en;zh" ]; then
      $DRY_RUN_CMD ${lib.getExe pkgs.flatpak} config --user --set languages "en;zh" || true
      $DRY_RUN_CMD ${lib.getExe pkgs.flatpak} --user --noninteractive update || true
    fi
  '';
}
