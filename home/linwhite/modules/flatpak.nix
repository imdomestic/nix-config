# Flathub apps for linwhite, installed per user by nix-flatpak; the system side
# (services.flatpak) comes with the desktop role. The host file lists the apps.
{inputs, ...}: {
  imports = [inputs.nix-flatpak.homeManagerModules.nix-flatpak];

  services.flatpak = {
    enable = true;
    update.auto = {
      enable = true;
      onCalendar = "weekly";
    };
  };
}
