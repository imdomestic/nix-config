{config, ...}: {
  boot.initrd.kernelModules = ["amdgpu"];
  boot.blacklistedKernelModules = ["nvidia_drm" "nvidia_modeset"];
  # 停用固件显示缓冲区，并由内核阻止加载 NVIDIA 显示模块。
  boot.kernelParams = [
    "initcall_blacklist=sysfb_init"
    "module_blacklist=nvidia_drm,nvidia_modeset"
  ];

  hardware = {
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
  services.xserver.videoDrivers = ["amdgpu" "nvidia"];

  services.udev.extraRules = ''
    SUBSYSTEM=="drm", ENV{DEVTYPE}=="drm_minor", KERNELS=="0000:01:00.0", TAG+="mutter-device-ignore"
    SUBSYSTEM=="drm", ENV{DEVTYPE}=="drm_minor", KERNELS=="0000:10:00.0", TAG+="mutter-device-preferred-primary"
  '';

  environment.sessionVariables = {
    DRI_PRIME = "pci-0000_10_00_0";
    __GLX_VENDOR_LIBRARY_NAME = "mesa";
    __EGL_VENDOR_LIBRARY_FILENAMES = "/run/opengl-driver/share/glvnd/egl_vendor.d/50_mesa.json";
    VK_LOADER_DRIVERS_SELECT = "radeon_icd*";
  };
}
