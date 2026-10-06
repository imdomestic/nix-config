{config, ...}: {
  imports = [../../modules/ssh];

  boot.blacklistedKernelModules = ["amdgpu" "radeon" "nvidia_drm" "nvidia_modeset"];
  # SSH 计算节点停用固件显示缓冲区及两张显卡的显示驱动。
  boot.kernelParams = [
    "initcall_blacklist=sysfb_init"
    "module_blacklist=amdgpu,radeon,nvidia_drm,nvidia_modeset"
  ];

  hardware = {
    # NVIDIA 计算运行库通过 /run/opengl-driver 提供给宿主机程序。
    graphics.enable = true;
    nvidia = {
      modesetting.enable = false;
      open = true;
      nvidiaSettings = false;
      nvidiaPersistenced = true;
      package = config.boot.kernelPackages.nvidiaPackages.production;
    };
    nvidia-container-toolkit.enable = true;
  };
  virtualisation.podman.enable = true;
  services = {
    xserver = {
      enable = false;
      videoDrivers = ["nvidia"];
    };
    displayManager.gdm.enable = false;
    desktopManager.gnome.enable = false;
    pipewire.enable = false;
    printing.enable = false;
  };
  systemd.defaultUnit = "multi-user.target";
  programs = {
    zsh.enable = true;
    nix-ld.enable = true;
  };
}
