# hank 在 tank 上的东西。这台没有 gui role,桌面工具单独列出。
{
  inputs,
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
    packages = ["com.github.rafostar.Clapper"];
    update = {
      onActivation = true;
      auto = {
        enable = true;
        onCalendar = "daily";
      };
    };
  };

  home.packages = with pkgs; [
    brightnessctl
    radeontop
  ];
}
