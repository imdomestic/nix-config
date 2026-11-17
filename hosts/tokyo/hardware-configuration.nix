{modulesPath, ...}: {
  imports = [(modulesPath + "/profiles/qemu-guest.nix")];
  boot.initrd.availableKernelModules = ["ata_piix" "uhci_hcd" "virtio_pci" "virtio_blk" "virtio_net"];
  boot.kernelParams = ["console=ttyS0,115200n8" "console=tty0"];
  # Aliyun boots via UEFI; the fallback path survives lost firmware entries.
  boot.loader.grub = {
    efiSupport = true;
    efiInstallAsRemovable = true;
  };
  zramSwap = {
    enable = true;
    priority = 100;
    memoryPercent = 50;
  };
}
