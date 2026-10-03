{
  config,
  lib,
  pkgs,
  inputs,
  ...
}: let
  cfg = config.my.windowsVM;
  virt = inputs.NixVirt.lib;
  domain = import ./windows-domain.nix {inherit config lib pkgs;};
  checkedDomain = overrides:
    virt.domain.writeXML (import ./windows-domain.nix {
      inherit lib pkgs;
      config = config // {my = config.my // {windowsVM = cfg // overrides;};};
    });
  checkedDomains = {
    desktop = checkedDomain {
      passthrough = false;
      hideHypervisor = false;
    };
    vfio = checkedDomain {
      passthrough = true;
      hideHypervisor = false;
    };
    hidden = checkedDomain {
      passthrough = true;
      hideHypervisor = true;
    };
  };
in {
  options.my.windowsVM = {
    installISO = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Absolute runtime path to a Windows installation ISO; null ejects the CD.";
    };
    passthrough = lib.mkEnableOption "exclusive Arc 140V passthrough (use the vfio specialisation)";
    hideHypervisor = lib.mkEnableOption "basic CPUID/KVM signature hiding, without timing concealment";
    memoryGiB = lib.mkOption {
      type = lib.types.ints.between 4 24;
      default = 16;
    };
    cores = lib.mkOption {
      type = lib.types.ints.between 2 6;
      default = 6;
    };
    igdROM = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../../../pkgs/vfio-igd-rom {};
      description = "Package containing igd-64a0.rom; initializes OpRegion, without pre-OS GOP output.";
    };
  };

  config = {
    assertions = [
      {
        assertion = cfg.installISO == null || lib.hasPrefix "/" cfg.installISO;
        message = "my.windowsVM.installISO must be an absolute runtime path.";
      }
    ];

    boot.kernelModules = ["kvm-intel"];
    boot.kernelParams = ["intel_iommu=on"];
    # VFIO devices cannot be saved or restored with libvirt managed save.
    virtualisation.libvirtd.onBoot = "ignore";
    virtualisation.libvirtd.onShutdown = "shutdown";
    virtualisation.libvirtd.shutdownTimeout = 90;
    virtualisation.libvirtd.qemu = {
      package = pkgs.qemu_kvm;
      runAsRoot = false;
      swtpm.enable = true;
    };
    programs.virt-manager.enable = true;
    virtualisation.libvirt = {
      enable = true;
      package = pkgs.libvirt;
      connections."qemu:///system" = {
        domains = [
          {
            definition = virt.domain.writeXML domain;
            # Preserve running state; a rebuild must not reset a Windows session.
            active = null;
            restart = false;
          }
        ];
        networks = [
          {
            definition = virt.network.writeXML (virt.network.templates.bridge {
              name = "windows";
              uuid = "b4a97c70-2f9d-4fd1-8131-9f0708c759ca";
              bridge_name = "virbr-win";
              subnet_byte = 178;
            });
            active = true;
            restart = false;
          }
        ];
        pools = [
          {
            definition = virt.pool.writeXML {
              name = "windows";
              uuid = "a6c5c0e0-6e2c-4738-866e-351b01fe9669";
              type = "dir";
              target.path = "/var/lib/libvirt/images/windows";
            };
            active = true;
            volumes = [
              {
                definition = virt.volume.writeXML {
                  name = "windows11.qcow2";
                  capacity = {
                    count = 240;
                    unit = "GiB";
                  };
                  allocation = {
                    count = 0;
                    unit = "GiB";
                  };
                  target.format.type = "qcow2";
                };
              }
            ];
          }
        ];
      };
    };

    networking.firewall.trustedInterfaces = ["virbr-win"];
    systemd.tmpfiles.rules = [
      "d /var/lib/libvirt/images/windows 0750 qemu-libvirtd qemu-libvirtd -"
      "d /var/lib/libvirt/iso 0755 root root -"
      "d /var/lib/libvirt/qemu/nvram 0750 qemu-libvirtd qemu-libvirtd -"
    ];
    systemd.services.nixvirt.after = ["systemd-tmpfiles-setup.service"];

    system.build.windowsVMChecks =
      pkgs.runCommand "268v-windows-vm-checks" {
        nativeBuildInputs = [pkgs.libvirt];
      } ''
        mkdir -p "$out"
        cp ${checkedDomains.desktop} "$out/desktop.xml"
        cp ${checkedDomains.vfio} "$out/vfio.xml"
        cp ${checkedDomains.hidden} "$out/vfio-hidden.xml"
        for definition in "$out"/*.xml; do
          virt-xml-validate "$definition" domain
        done
        ${pkgs.python3}/bin/python ${../../../scripts/check-windows-vm-qemu.py} \
          ${config.virtualisation.libvirtd.qemu.package}/bin/qemu-system-x86_64 "$out"/*.xml
        test -s ${cfg.igdROM}/igd-64a0.rom
        test -f ${pkgs.OVMFFull.fd}/FV/OVMF_CODE.fd
        test -f ${pkgs.OVMFFull.fd}/FV/OVMF_VARS.fd
        test -f ${pkgs.virtio-win.src}
      '';

    # Reserve the only GPU at boot; see docs/268v-windows-vfio.md.
    specialisation.vfio.configuration = {
      my.windowsVM.passthrough = true;
      system.nixos.tags = ["vfio"];
      boot.kernelParams = ["vfio-pci.ids=8086:64a0" "initcall_blacklist=sysfb_init"];
      # nixos-hardware explicitly loads xe; a modprobe blacklist alone cannot override that.
      boot.initrd.kernelModules = lib.mkForce ["dm_mod" "vfio" "vfio_pci" "vfio_iommu_type1"];
      boot.blacklistedKernelModules = ["xe" "i915"];
      services.displayManager.gdm.enable = lib.mkForce false;
      systemd.services.display-manager.enable = lib.mkForce false;
      systemd.defaultUnit = "multi-user.target";
      services.logind.settings.Login = {
        HandleLidSwitch = "ignore";
        HandleLidSwitchExternalPower = "ignore";
      };
    };
  };
}
