{
  config,
  lib,
  pkgs,
}: let
  cfg = config.my.windowsVM;
  # Use Secure Boot capable firmware with unenrolled keys for the unsigned IGD ROM.
  firmware = pkgs.OVMFFull.fd;
in
  {
    type = "kvm";
    name = "windows11";
    uuid = "dce42db7-5a5e-4d41-9c2a-06268a000011";
    memory = {
      count = cfg.memoryGiB;
      unit = "GiB";
    };
    vcpu.count = cfg.cores;
    os = {
      type = "hvm";
      arch = "x86_64";
      machine = "pc-q35-10.2";
      loader = {
        readonly = true;
        type = "pflash";
        path = "${firmware}/FV/OVMF_CODE.fd";
      };
      nvram = {
        template = "${firmware}/FV/OVMF_VARS.fd";
        path = "/var/lib/libvirt/qemu/nvram/windows11_VARS.fd";
      };
      boot = [{dev = "hd";} {dev = "cdrom";}];
      bootmenu.enable = true;
    };
    features =
      {
        acpi = {};
        apic = {};
        vmport.state = false;
        kvm.hidden.state = cfg.hideHypervisor;
      }
      // lib.optionalAttrs (!cfg.hideHypervisor) {
        hyperv = {
          mode = "custom";
          relaxed.state = true;
          vapic.state = true;
          spinlocks = {
            state = true;
            retries = 8191;
          };
        };
      };
    cpu = {
      mode = "host-passthrough";
      migratable = false;
      topology = {
        sockets = 1;
        cores = cfg.cores;
        threads = 1;
      };
      feature = lib.optional cfg.hideHypervisor {
        policy = "disable";
        name = "hypervisor";
      };
    };
    clock = {
      offset = "localtime";
      timer =
        [
          {
            name = "rtc";
            tickpolicy = "catchup";
          }
          {
            name = "pit";
            tickpolicy = "delay";
          }
          {
            name = "hpet";
            present = false;
          }
        ]
        ++ lib.optional (!cfg.hideHypervisor) {
          name = "hypervclock";
          present = true;
        };
    };
    pm = {
      suspend-to-mem.enabled = false;
      suspend-to-disk.enabled = false;
    };
    devices = {
      emulator = "${config.virtualisation.libvirtd.qemu.package}/bin/qemu-system-x86_64";
      disk = [
        {
          type = "file";
          device = "disk";
          driver = {
            name = "qemu";
            type = "qcow2";
            cache = "none";
            discard = "unmap";
          };
          source.file = "/var/lib/libvirt/images/windows/windows11.qcow2";
          target = {
            dev = "vda";
            bus = "virtio";
          };
        }
        {
          type = "file";
          device = "cdrom";
          driver = {
            name = "qemu";
            type = "raw";
          };
          source =
            if cfg.installISO == null
            then null
            else {
              file = cfg.installISO;
              startupPolicy = "mandatory";
            };
          target = {
            dev = "sda";
            bus = "sata";
          };
          readonly = true;
        }
        {
          type = "file";
          device = "cdrom";
          driver = {
            name = "qemu";
            type = "raw";
          };
          source.file = "${pkgs.virtio-win.src}";
          target = {
            dev = "sdb";
            bus = "sata";
          };
          readonly = true;
        }
      ];
      interface = {
        type = "network";
        source.network = "windows";
        model.type = "virtio";
        mac.address = "52:54:00:26:80:11";
      };
      controller = [
        {
          type = "usb";
          model = "qemu-xhci";
          index = 0;
        }
      ];
      input = [
        {
          type = "tablet";
          bus = "usb";
        }
        {
          type = "keyboard";
          bus = "ps2";
        }
      ] ++ lib.optionals cfg.localInput [
        {
          type = "evdev";
          source = {
            dev = "/dev/input/by-path/platform-i8042-serio-0-event-kbd";
            grab = "all";
            grabToggle = "ctrl-ctrl";
            repeat = true;
          };
        }
        {
          type = "evdev";
          source.dev = "/dev/input/by-path/pci-0000:00:19.0-platform-i2c_designware.3-event-mouse";
        }
      ];
      graphics = {
        type = "spice";
        autoport = true;
        listen = {
          type = "address";
          address = "127.0.0.1";
        };
        gl.enable = false;
      };
      # Explicit none prevents libvirt from adding a fallback video device.
      video.model =
        if cfg.softwareDisplay
        then {
          type = "vga";
          primary = true;
        }
        else {type = "none";};
      sound.model = "ich9";
      audio = {
        id = 1;
        type = "spice";
      };
      tpm = {
        model = "tpm-crb";
        backend = {
          type = "emulator";
          version = "2.0";
        };
      };
      memballoon.model = "none";
      hostdev = lib.optional cfg.passthrough {
        mode = "subsystem";
        type = "pci";
        managed = false;
        source.address = {
          domain = 0;
          bus = 0;
          slot = 2;
          function = 0;
        };
        # Match the upstream IGD layout; see docs/268v-windows-vfio.md.
        address = {
          type = "pci";
          domain = 0;
          bus = 0;
          slot = 2;
          function = 0;
        };
        rom = {
          bar = true;
          file = "${cfg.igdROM}/igd-64a0.rom";
        };
      };
    };
  }
  // lib.optionalAttrs cfg.passthrough {
    qemu-override = {
      device = [
        {
          alias = "hostdev0";
          frontend.property = [
            {
              name = "x-igd-opregion";
              type = "bool";
              value = "true";
            }
            {
              name = "x-igd-legacy-mode";
              # QEMU exposes OnOffAuto, not bool; see docs/incidents.md#268v-vfio-qemu-property-type.
              type = "string";
              value = "off";
            }
          ];
        }
      ];
    };
  }
