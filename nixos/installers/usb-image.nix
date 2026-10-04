{pkgs, ...}: {
  system.build.usbImageBuilder = pkgs.writeShellApplication {
    name = "build-rescue-usb-image";
    runtimeInputs = with pkgs; [coreutils util-linux dosfstools gptfdisk systemdMinimal xorriso jq];
    text = ''
      test "$#" -eq 2
      test "$(id -u)" -eq 0
      umask 077
      iso=$(realpath "$1")
      work=$(realpath -m "$2")
      test -s "$iso"
      test "$(blkid -p -s LABEL -o value "$iso")" = NIXOS_RESCUE
      install -d -m 0700 "$work" "$work/iso" "$work/esp" "$work/build-tmp"
      export TMPDIR="$work/build-tmp"
      test ! -e "$work/rescue-usb.img"
      data=$work/rescue-data.iso
      test ! -e "$data"
      mount -o loop,ro "$iso" "$work/iso"
      xorriso -as mkisofs -volid NIXOS_RESCUE -iso-level 3 -r \
        -o "$data" "$work/iso"
      wipefs --json "$data" |
        jq -e '.signatures | length == 1 and .[0].type == "iso9660"'
      iso_mib=$(( ($(stat -c %s "$data") + 1048575) / 1048576 ))
      data_mib=$(( (iso_mib + 127) / 128 * 128 ))
      disk_mib=$(( (data_mib + 516 + 255) / 256 * 256 ))
      truncate -s "''${disk_mib}M" "$work/rescue-usb.img"
      sgdisk --clear \
        --new=1:2048:+512M --typecode=1:ef00 --change-name=1:NixOS-Rescue-EFI \
        --new=2:0:+2M --typecode=2:ef02 --change-name=2:GRUB-BIOS \
        --new="3:0:+''${data_mib}M" --typecode=3:8300 --change-name=3:NixOS-Rescue \
        "$work/rescue-usb.img"
      loop=$(losetup --find --show --partscan "$work/rescue-usb.img")
      udevadm settle
      test "$(lsblk -dn -o TYPE "$loop")" = loop
      mkfs.vfat -F 32 -n RESCUE_EFI "''${loop}p1"
      dd if="$data" of="''${loop}p3" bs=4M conv=fsync status=progress
      mount "''${loop}p1" "$work/esp"
      ${pkgs.grub2_efi}/bin/grub-install --target=x86_64-efi \
        --directory=${pkgs.grub2_efi}/lib/grub/x86_64-efi \
        --efi-directory="$work/esp" --boot-directory="$work/esp/boot" \
        --removable --no-nvram "$loop"
      ${pkgs.grub2}/bin/grub-install --target=i386-pc \
        --directory=${pkgs.grub2}/lib/grub/i386-pc \
        --boot-directory="$work/esp/boot" "$loop"
      cp "$work/iso/boot/grub/grub.cfg" "$work/esp/boot/grub/grub.cfg"
      ${pkgs.grub2}/bin/grub-script-check "$work/esp/boot/grub/grub.cfg"
      test -s "$work/esp/EFI/BOOT/BOOTX64.EFI"
      test -s "$work/esp/boot/grub/i386-pc/core.img"
      sync
      umount "$work/esp"
      umount "$work/iso"
      fsck.vfat -n "''${loop}p1"
      blkid "''${loop}p1" "''${loop}p3"
      sgdisk --print --verify "$loop"
      losetup --detach "$loop"
      sha256sum "$work/rescue-usb.img"
    '';
  };
}
