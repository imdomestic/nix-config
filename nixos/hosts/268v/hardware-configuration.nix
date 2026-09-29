{
  config,
  lib,
  modulesPath,
  ...
}: {
  imports = [(modulesPath + "/installer/scan/not-detected.nix")];

  boot.initrd.availableKernelModules = ["nvme" "xhci_pci" "thunderbolt" "usbhid" "uas" "sd_mod"];
  boot.kernelModules = ["kvm-intel"];

  # Windows G: on the SK hynix SSD; retain its GPT identity when formatting.
  fileSystems."/" = {
    device = "/dev/disk/by-partuuid/f6be7d9c-1049-4646-9da3-c04e702303f0";
    fsType = "ext4";
  };
  fileSystems."/boot" = {
    device = "/dev/disk/by-label/NIXBOOT268V";
    fsType = "vfat";
    options = ["umask=0077"];
  };
  # Share the existing ESP without formatting it; kernels live on XBOOTLDR.
  fileSystems."/efi" = {
    device = "/dev/disk/by-partuuid/361e2715-9524-45f5-892f-2d21148a45d4";
    fsType = "vfat";
    options = ["umask=0077"];
  };

  swapDevices = [];
  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;
}
