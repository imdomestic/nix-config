{ inputs, lib, system, hostUsers ? {}, usernames ? [], ... }:
let
  pkgs = inputs.nixpkgs.legacyPackages.${system};
  isDarwin = lib.hasSuffix "darwin" system;
  defaultGroups =
    [
      "wheel"
      "networkmanager"
    ]
    ++ lib.optionals (!isDarwin) [
      "video"
      "audio"
      "disk"
      "libvirt"
      "libvirtd"
      "qemu-libvirtd"
      "podman"
      "dialout"
    ];

  allUsers =
    lib.unique (
      usernames
      ++ builtins.attrNames hostUsers
    );

  mkUser = name:
    let
      overrides = hostUsers.${name} or {};
      explicitGroups =
        if overrides ? extraGroups
        then overrides.extraGroups
        else defaultGroups;
      linuxHome = "/home/${name}";
      darwinHome = "/Users/${name}";
      defaultAttrs =
        {
          description =
            if overrides ? description
            then overrides.description
            else name;
          shell =
            if overrides ? shell
            then overrides.shell
            else pkgs.zsh;
        }
        // lib.optionalAttrs (!isDarwin) {
          isNormalUser =
            if overrides ? isNormalUser
            then overrides.isNormalUser
            else true;
          extraGroups = explicitGroups;
          home =
            if overrides ? home && lib.isString overrides.home
            then overrides.home
            else linuxHome;
        }
        // lib.optionalAttrs isDarwin {
          home =
            if overrides ? home && lib.isString overrides.home
            then overrides.home
            else darwinHome;
        };
    in
      lib.recursiveUpdate defaultAttrs (overrides.nixos or {});
in {
  users.users = lib.genAttrs allUsers mkUser;
}
