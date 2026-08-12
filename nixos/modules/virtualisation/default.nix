{pkgs, ...}: {
  environment.systemPackages = with pkgs; [
    virt-manager
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
    # cockpit-machines 跟着 cockpit 一起删了(见 profiles/server.nix)——
    # 它是 cockpit 的虚拟机插件,宿主没了就只是个装着没用的包。
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
