{pkgs, ...}: {
  environment.systemPackages = with pkgs; [
    cloud-utils
    cdrtools
    qemu
    libguestfs
    virt-viewer
    spice
    spice-gtk
    spice-protocol
    virtio-win
    win-spice
    dive
    podman-compose
  ];

  virtualisation = {
    containers.enable = true;
    containerd = {
      enable = true;
    };
    podman = {
      enable = true;
      dockerCompat = true;
      defaultNetwork.settings.dns_enabled = true;
    };
    libvirtd = {
      enable = true;
      qemu = {
        swtpm.enable = true;
        runAsRoot = true;
        # ovmf.enable = true;
        # ovmf.packages = [pkgs.OVMFFull.fd];
      };
    };
    spiceUSBRedirection.enable = true;
  };
  programs.virt-manager = {
    enable = true;
  };
}
