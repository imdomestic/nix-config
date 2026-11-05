{lib, ...}: {
  imports = [
    ../modules/nerdfonts
    ../modules/fcitx5
    ../modules/ssh
  ];

  # Core desktop expectations
  services = {
    displayManager.gdm.enable = lib.mkDefault true;
    desktopManager.gnome.enable = lib.mkDefault true;
  };

  services.pipewire = {
    enable = lib.mkDefault true;
    pulse.enable = lib.mkDefault true;
    jack.enable = lib.mkDefault true;
  };

  services.printing.enable = lib.mkDefault true;
  # 账户的 home 用 nix-flatpak 装应用(hank-flatpak),它要系统侧的 flatpak。
  services.flatpak.enable = lib.mkDefault true;

  hardware = {
    bluetooth.enable = lib.mkDefault true;
    # pulseaudio.enable = lib.mkDefault false;
    graphics.enable = lib.mkDefault true;
  };

  programs = {
    zsh.enable = lib.mkDefault true;
    nix-ld.enable = lib.mkDefault true;
  };

  environment.sessionVariables = {
    # 统一 Wayland 下非 GTK 原生应用 (GLFW, Qt, XWayland) 的光标大小，避免部分窗口光标放大
    XCURSOR_SIZE = "24";
  };
}
