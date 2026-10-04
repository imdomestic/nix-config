{config, ...}: {
  boot.initrd.kernelModules = ["amdgpu"];
  boot.blacklistedKernelModules = ["nvidia_drm" "nvidia_modeset"];

  hardware.nvidia = {
    modesetting.enable = false;
    open = true;
    nvidiaSettings = false;
    package = config.boot.kernelPackages.nvidiaPackages.production;
  };
  services.xserver.videoDrivers = ["amdgpu" "nvidia"];

  services.udev.extraRules = ''
    SUBSYSTEM=="drm", ENV{DEVTYPE}=="drm_minor", ENV{DEVNAME}=="/dev/dri/card[0-9]", SUBSYSTEMS=="pci", ATTRS{vendor}=="0x1002", ATTRS{device}=="0x13c0", TAG+="mutter-device-preferred-primary"
  '';

  environment.sessionVariables = {
    DRI_PRIME = "pci-0000_10_00_0";
    __GLX_VENDOR_LIBRARY_NAME = "mesa";
    __EGL_VENDOR_LIBRARY_FILENAMES = "/run/opengl-driver/share/glvnd/egl_vendor.d/50_mesa.json";
    VK_LOADER_DRIVERS_SELECT = "radeon_icd*";
  };
}
