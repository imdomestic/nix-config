{
  config,
  lib,
  modulesPath,
  pkgs,
  ...
}: let
  squashfs = pkgs.callPackage (modulesPath + "/../lib/make-squashfs.nix") {
    storeContents = config.isoImage.storeContents;
    comp = config.isoImage.squashfsCompression;
  };
  biosMenu = pkgs.writeText "rescue-grub.cfg" ''
    search --no-floppy --file --set=root /EFI/nixos-installer-image
    configfile /EFI/BOOT/grub.cfg
  '';
  efiImage =
    (lib.findFirst (entry: entry.target == "/boot/efi.img")
      (throw "The rescue image requires an EFI boot image")
      config.isoImage.contents).source;
  contents =
    config.isoImage.contents
    ++ [
      {
        source = squashfs;
        target = "/nix-store.squashfs";
      }
      {
        source = biosMenu;
        target = "/boot/grub/grub.cfg";
      }
    ];
in {
  # UEFI 使用 NixOS 的 GRUB 镜像，BIOS 与 USB MBR 由 grub-mkrescue 生成。
  isoImage.makeBiosBootable = false;
  system.build.isoImage = lib.mkForce (pkgs.runCommand config.image.baseName {
      __structuredAttrs = true;
      nativeBuildInputs = [pkgs.grub2 pkgs.xorriso];
      unsafeDiscardReferences.out = true;
    } ''
      mkdir -p "$out/iso"
      grub-script-check ${biosMenu}
      grub-mkrescue \
        --directory=${pkgs.grub2}/lib/grub/i386-pc \
        --output="$out/iso/${config.image.baseName}.iso" \
        -volid ${lib.escapeShellArg config.isoImage.volumeID} \
        -iso-level 3 -r \
        ${lib.escapeShellArgs (map (entry: "${entry.target}=${entry.source}") contents)} \
        -eltorito-alt-boot -e --interval:appended_partition_2:all:: -no-emul-boot \
        -append_partition 2 0xef ${efiImage} -appended_part_as_gpt
    '');
}
