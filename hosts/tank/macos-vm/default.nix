# The macOS guest that carries maxx's iMessage bridge: Messages.app, imsg and
# the max repo's bridge/imsg, reachable from tank and from nothing else.
# Why a guest on tank: docs/decisions.md#macos-vm. Installing it and what
# runs inside: docs/runbooks/macos-vm.md.
{
  config,
  lib,
  pkgs,
  ...
}: let
  user = "macos-vm";
  tap = "macos0";
  hostAddress = "10.234.0.1";
  guestAddress = "10.234.0.2";
  stateDir = "/data/services/macos-vm";
  runDir = "/run/macos-vm";
  # 5947; well away from 5900, which gnome-remote-desktop may want.
  vncDisplay = 47;

  # OSX-KVM at the commit that added Tahoe: its OVMF build, its tested
  # OpenCore image, and fetch-macOS-v2.py for the runbook.
  osxKvm = pkgs.fetchFromGitHub {
    owner = "kholia";
    repo = "OSX-KVM";
    rev = "4c378a4b5e0b219783683012bec680325eb40719";
    hash = "sha256-BmMWWGkNtZwEH9utoc3Mj5gGCjlgIicGsTEPxAxG7hw=";
  };

  # The EFI tree inside OSX-KVM's OpenCore.qcow2, untouched. (The repo's
  # loose OpenCore/EFI has a different kext set than the image it tested.)
  opencoreEfi =
    pkgs.runCommand "macos-vm-opencore-efi" {
      nativeBuildInputs = with pkgs; [qemu-utils mtools gptfdisk gawk];
    } ''
      qemu-img convert -O raw ${osxKvm}/OpenCore/OpenCore.qcow2 oc.raw
      first=$(sgdisk -i 1 oc.raw | awk '/^First sector/ {print $3}')
      export MTOOLS_SKIP_CHECK=1
      mcopy -s -i "oc.raw@@$((first * 512))" ::/EFI .
      mkdir -p $out
      cp -r EFI $out/
    '';

  secret = name: config.sops.secrets."macos-vm/${name}".path;

  # One QMP command, given as JSON.
  qmp = pkgs.writeShellApplication {
    name = "macos-vm-qmp";
    runtimeInputs = [pkgs.socat];
    text = ''
      printf '{"execute":"qmp_capabilities"}\n%s\n' "$1" |
        socat -t 2 - UNIX-CONNECT:${runDir}/qmp.sock >/dev/null
    '';
  };

  prepare = pkgs.writeShellApplication {
    name = "macos-vm-prepare";
    runtimeInputs = with pkgs; [coreutils gawk python3 gptfdisk dosfstools mtools openssh];
    text = ''
      umask 077
      # What the first start creates and later starts keep.
      [ -e ${stateDir}/OVMF_VARS.fd ] ||
        install -m 600 ${osxKvm}/OVMF_VARS-1920x1080.fd ${stateDir}/OVMF_VARS.fd
      # Raw, not qcow2: APFS inside already copies on write. Not bcachefs
      # nocow either: the install came out corrupt on it
      # (docs/incidents.md#macos-vm-nocow).
      [ -e ${stateDir}/mac_hdd.img ] || truncate -s 80G ${stateDir}/mac_hdd.img
      [ -e ${stateDir}/stop_key ] ||
        ssh-keygen -q -t ed25519 -N "" -C macos-vm-stop -f ${stateDir}/stop_key

      cd ${runDir}
      rm -rf esp opencore.img
      cp -r --no-preserve=mode ${opencoreEfi}/EFI esp
      # iMac20,1: Tahoe still supports it, so an upgrade keeps the identity
      # Messages was activated with. 0x877 is what `csrutil disable` sets;
      # imsg's IMCore helper needs SIP off.
      python3 ${./opencore.py} esp/OC/config.plist \
        --product iMac20,1 --csr 77080000 \
        --serial ${secret "serial"} --mlb ${secret "mlb"} \
        --rom ${secret "rom"} --uuid ${secret "uuid"}

      truncate -s 64M opencore.img
      sgdisk -o -n 1:2048:0 -t 1:ef00 -c 1:OPENCORE opencore.img >/dev/null
      first=$(sgdisk -i 1 opencore.img | awk '/^First sector/ {print $3}')
      last=$(sgdisk -i 1 opencore.img | awk '/^Last sector/ {print $3}')
      mkfs.fat -n OPENCORE --offset="$first" opencore.img $(((last - first + 1) / 2)) >/dev/null
      export MTOOLS_SKIP_CHECK=1
      mmd -i "opencore.img@@$((first * 512))" ::/EFI
      mcopy -s -i "opencore.img@@$((first * 512))" esp/* ::/EFI/
      rm -rf esp
    '';
  };

  start = pkgs.writeShellApplication {
    name = "macos-vm";
    runtimeInputs = with pkgs; [coreutils gnused qemu_kvm];
    text = ''
      # en0's MAC is the ROM from the identity, as Apple's activation expects.
      mac=$(tr -d ' :\n' < ${secret "rom"} | sed 's/../&:/g; s/:$//')
      installer=()
      if [ -e ${stateDir}/BaseSystem.img ]; then
        installer=(
          -drive "id=InstallMedia,if=none,format=raw,file=${stateDir}/BaseSystem.img"
          -device "ide-hd,bus=sata.3,drive=InstallMedia"
        )
      fi
      # The CPU line is OSX-KVM's for Sequoia and Tahoe; on this Haswell host
      # QEMU drops the Skylake features the hardware lacks (`check` warns).
      # The NIC sits at 00:12, a slot the template's DeviceProperties mark
      # built-in, which iMessage requires of en0.
      exec qemu-system-x86_64 \
        -name macos-vm,process=macos-vm \
        -machine q35,accel=kvm \
        -cpu Skylake-Client,-hle,-rtm,kvm=on,vendor=GenuineIntel,+invtsc,vmware-cpuid-freq=on,+ssse3,+sse4.2,+popcnt,+avx,+aes,+xsave,+xsaveopt,check \
        -smp 4,cores=4,sockets=1 \
        -m 8192 \
        -device qemu-xhci,id=xhci \
        -device usb-kbd,bus=xhci.0 \
        -device usb-tablet,bus=xhci.0 \
        -device isa-applesmc,osk="ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc" \
        -drive if=pflash,format=raw,readonly=on,file=${osxKvm}/OVMF_CODE_4M.fd \
        -drive if=pflash,format=raw,file=${stateDir}/OVMF_VARS.fd \
        -smbios type=2 \
        -device ich9-ahci,id=sata \
        -drive id=OpenCoreBoot,if=none,format=raw,snapshot=on,file=${runDir}/opencore.img \
        -device ide-hd,bus=sata.2,drive=OpenCoreBoot \
        -drive id=MacHDD,if=none,format=raw,discard=unmap,file=${stateDir}/mac_hdd.img \
        -device ide-hd,bus=sata.4,drive=MacHDD \
        "''${installer[@]}" \
        -netdev tap,id=net0,ifname=${tap},script=no,downscript=no,vhost=on \
        -device virtio-net-pci,netdev=net0,mac="$mac",bus=pcie.0,addr=0x12 \
        -device vmware-svga \
        -display none \
        -vnc 127.0.0.1:${toString vncDisplay},password=on \
        -qmp unix:${runDir}/qmp.sock,server=on,wait=off \
        -monitor none
    '';
  };

  # QEMU's VNC refuses everyone until it has a password.
  vncPassword = pkgs.writeShellApplication {
    name = "macos-vm-vnc-password";
    runtimeInputs = [pkgs.coreutils qmp];
    text = ''
      for _ in $(seq 50); do
        [ -S ${runDir}/qmp.sock ] && break
        sleep 0.2
      done
      password=$(tr -d '\n' < ${secret "vnc-password"})
      macos-vm-qmp "{\"execute\":\"change-vnc-password\",\"arguments\":{\"password\":\"$password\"}}"
    '';
  };

  # macOS ignores the ACPI power button unless someone answers its dialog,
  # so a clean stop asks the guest itself: the guest lets this key run
  # `shutdown -h now` and nothing else (runbook). The power button is the
  # fallback for a guest that isn't set up yet; systemd kills QEMU after.
  stop = pkgs.writeShellApplication {
    name = "macos-vm-stop";
    runtimeInputs = [pkgs.coreutils pkgs.openssh qmp];
    text = ''
      ssh -i ${stateDir}/stop_key -o BatchMode=yes -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${stateDir}/known_hosts \
        max@${guestAddress} ||
        macos-vm-qmp '{"execute":"system_powerdown"}' || true
      for _ in $(seq 120); do
        kill -0 "$MAINPID" 2>/dev/null || exit 0
        sleep 1
      done
    '';
  };
in {
  users.users.${user} = {
    isSystemUser = true;
    group = user;
    home = stateDir;
    extraGroups = ["kvm"];
  };
  users.groups.${user} = {};

  sops.secrets = lib.genAttrs (map (n: "macos-vm/${n}") ["serial" "mlb" "rom" "uuid" "vnc-password"]) (_: {
    owner = user;
  });

  systemd.tmpfiles.rules = ["d ${stateDir} 0700 ${user} ${user} -"];

  # A /30 of its own; the guest gets .2 from networkd's DHCP server and
  # nothing else exists on the link.
  systemd.network.netdevs."40-${tap}" = {
    netdevConfig = {
      Kind = "tap";
      Name = tap;
    };
    tapConfig = {
      User = user;
      Group = user;
      VNetHeader = true;
    };
  };
  systemd.network.networks."40-${tap}" = {
    matchConfig.Name = tap;
    address = ["${hostAddress}/30"];
    networkConfig = {
      DHCPServer = true;
      ConfigureWithoutCarrier = true;
      # QEMU restarting must not make networkd reconfigure the link.
      IgnoreCarrierLoss = true;
      LinkLocalAddressing = "no";
      IPv6AcceptRA = false;
      IPv4Forwarding = true;
    };
    dhcpServerConfig = {
      PoolOffset = 2;
      PoolSize = 1;
      EmitDNS = true;
      # The same public resolvers maxx's VMs use; the guest can't reach the
      # LAN's.
      DNS = ["223.5.5.5" "119.29.29.29"];
    };
    linkConfig.RequiredForOnline = "no";
  };

  # nixos-fw runs after the table below and would drop the guest's DHCP.
  networking.firewall.interfaces.${tap}.allowedUDPPorts = [67];

  # The guest runs with SIP off and an Apple ID signed in: it reaches the
  # internet and nothing private. Same shape as maxx's own VM table; tank's
  # forward chain filters nothing else (filterForward is off), and its
  # input has ports open on every interface, which this shields.
  networking.nftables.tables.macos-vm = {
    family = "inet";
    content = ''
      set non_public_v4 {
        type ipv4_addr
        flags interval
        elements = {
          0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
          169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
          192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15,
          198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4
        }
      }
      chain input {
        type filter hook input priority -10; policy accept;
        iifname "${tap}" ct state { established, related } accept
        iifname "${tap}" udp dport 67 accept
        iifname "${tap}" counter reject with icmpx type admin-prohibited
      }
      chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "${tap}" meta nfproto ipv6 counter reject with icmpx type admin-prohibited
        iifname "${tap}" ip saddr != ${guestAddress} counter drop
        iifname "${tap}" ip daddr @non_public_v4 counter reject with icmpx type admin-prohibited
        iifname "${tap}" oifname "tailscale*" counter drop
        oifname "${tap}" ct state != { established, related } counter drop
      }
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr ${guestAddress} oifname "br-lan" masquerade
      }
    '';
  };

  systemd.services.macos-vm = {
    description = "macOS guest for maxx's iMessage bridge";
    wantedBy = ["multi-user.target"];
    requires = ["sys-subsystem-net-devices-${tap}.device"];
    after = ["sys-subsystem-net-devices-${tap}.device" "systemd-networkd.service"];
    serviceConfig = {
      User = user;
      Group = user;
      RuntimeDirectory = "macos-vm";
      RuntimeDirectoryMode = "0700";
      ExecStartPre = lib.getExe prepare;
      ExecStart = lib.getExe start;
      ExecStartPost = lib.getExe vncPassword;
      ExecStop = lib.getExe stop;
      TimeoutStopSec = 150;
      Restart = "on-failure";
      RestartSec = 30;
      ReadWritePaths = [stateDir];
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      NoNewPrivileges = true;
      DevicePolicy = "closed";
      DeviceAllow = ["/dev/kvm rw" "/dev/net/tun rw" "/dev/vhost-net rw"];
    };
  };
}
