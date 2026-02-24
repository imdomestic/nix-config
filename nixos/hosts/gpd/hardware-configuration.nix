{ config, lib, pkgs, modulesPath, ... }:

{
  imports =
    [ (modulesPath + "/installer/scan/not-detected.nix")
    ];

  boot.initrd.availableKernelModules = [ "xhci_pci" "ahci" "usbhid" "usb_storage" "sd_mod" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];

  fileSystems."/" =
    { device = "/dev/disk/by-uuid/fc32d49c-4343-45d7-b5be-8bdce8ae6c53";
      fsType = "ext4";
    };

  fileSystems."/boot" =
    { device = "/dev/disk/by-uuid/23D4-1380";
      fsType = "vfat";
      options = [ "fmask=0022" "dmask=0022" ];
    };

  swapDevices = [ ];

  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;

  ###### 1) 屏幕旋转（TTY 生效）
  # Pocket 2：物理竖屏面板，建议顺时针 90°
  boot.kernelParams = [ "fbcon=rotate:1" ];

  ###### 2) TTY 字体放大（高分屏必需）
  console = {
    packages = [ pkgs.terminus_font ];
    font = "ter-v36n";  # 觉得小就改 ter-v36n
  };

  ###### 7) 小屏触控板/键盘体验（可选）
  services.libinput = {
    enable = true;
    touchpad = {
      naturalScrolling = true;
      tapping = true;
      accelProfile = "adaptive";
    };
  };
}
