{
  config,
  lib,
  pkgs,
  inputs,
}: let
  host = config;
  guest = inputs.nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      ({modulesPath, ...}: {
        imports = [(modulesPath + "/profiles/minimal.nix")];
        nixpkgs.pkgs = pkgs;
        system.stateVersion = "26.05";
        networking.hostName = "vfio-linux-probe";
        networking.useDHCP = false;
        boot.kernelPackages = host.boot.kernelPackages;
        boot.loader.grub.enable = false;
        boot.initrd.availableKernelModules = ["9p" "9pnet_virtio" "virtio_pci"];
        boot.kernelParams = ["console=ttyS0,115200" "panic=30"];
        fileSystems."/" = {
          device = "tmpfs";
          fsType = "tmpfs";
          options = ["mode=755"];
        };
        fileSystems."/nix/store" = {
          device = "nix-store";
          fsType = "9p";
          neededForBoot = true;
          options = ["trans=virtio" "version=9p2000.L" "msize=262144" "ro"];
        };
        hardware.enableAllFirmware = true;
        hardware.graphics.enable = true;
        nix.enable = false;
        systemd.services."serial-getty@ttyS0".enable = false;
        systemd.services.vfio-probe = {
          wantedBy = ["multi-user.target"];
          after = ["systemd-udev-trigger.service" "systemd-tmpfiles-setup.service"];
          path = with pkgs; [bash coreutils pciutils util-linux systemd drm_info vulkan-tools];
          environment.XDG_RUNTIME_DIR = "/run/vfio-probe";
          serviceConfig = {
            Type = "oneshot";
            RuntimeDirectory = "vfio-probe";
            TimeoutStartSec = 240;
            ExecStart = "${pkgs.bash}/bin/bash ${../../../scripts/vfio-probe/linux-guest.sh}";
            ExecStopPost = "${pkgs.systemd}/bin/systemctl --no-block poweroff";
          };
        };
      })
    ];
  };
  mkDomain = passthrough: let
    base = import ./windows-domain.nix {
      inherit lib pkgs;
      config =
        host
        // {
          my =
            host.my
            // {
              windowsVM =
                host.my.windowsVM
                // {
                  inherit passthrough;
                  hideHypervisor = true;
                };
            };
        };
    };
  in
    base
    // {
      name = "vfio-linux-probe";
      uuid = "dce42db7-5a5e-4d41-9c2a-06268a000012";
      on_poweroff = "destroy";
      on_reboot = "destroy";
      on_crash = "destroy";
      os =
        base.os
        // {
          nvram = base.os.nvram // {path = "/var/lib/libvirt/qemu/nvram/vfio-linux-probe_VARS.fd";};
          kernel.path = "${guest.config.system.build.kernel}/bzImage";
          initrd.path = "${guest.config.system.build.initialRamdisk}/initrd";
          cmdline.options = "init=${guest.config.system.build.toplevel}/init ${lib.concatStringsSep " " guest.config.boot.kernelParams}";
        };
      devices =
        (builtins.removeAttrs base.devices ["disk" "interface" "tpm"])
        // {
          filesystem = {
            type = "mount";
            accessmode = "passthrough";
            source.dir = "/nix/store";
            target.dir = "nix-store";
            readonly = true;
          };
        };
      # NixVirt 0.6 cannot express a file source for serial; retain only this fragment.
      qemu-commandline.arg = [
        {value = "-serial";}
        {value = "file:/var/lib/libvirt/qemu/vfio-linux-probe-serial.log";}
      ];
    };
  normal = inputs.NixVirt.lib.domain.writeXML (mkDomain false);
  vfio = inputs.NixVirt.lib.domain.writeXML (mkDomain true);
in
  pkgs.runCommand "268v-vfio-linux-probe" {
    nativeBuildInputs = [pkgs.libvirt];
  } ''
    mkdir -p "$out"
    cp ${normal} "$out/desktop.xml"
    cp ${vfio} "$out/vfio.xml"
    for definition in "$out"/*.xml; do
      virt-xml-validate "$definition" domain
    done
    ${pkgs.python3}/bin/python ${../../../scripts/check-windows-vm-qemu.py} \
      ${host.virtualisation.libvirtd.qemu.package}/bin/qemu-system-x86_64 "$out"/*.xml
    ln -s ${guest.config.system.build.toplevel} "$out/guest-system"
  ''
