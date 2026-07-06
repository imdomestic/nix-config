{
  lib,
  pkgs,
  config,
  ...
}: let
  inherit (config.my.host) users usernames;
  isDarwin = lib.hasSuffix "darwin" config.my.host.system;
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

  allUsers = lib.unique (
    usernames
    ++ builtins.attrNames users
  );

  mkUser = name: let
    overrides = users.${name} or {};
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
