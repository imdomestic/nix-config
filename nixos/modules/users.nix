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

  # macOS 上光写 users.users.<name>.shell 是不生效的:nix-darwin 只对
  # users.knownUsers 里的账户动 dscl,其余的声明了也只是躺在配置里。所以这台 mac 的
  # 登录 shell 一直是 /bin/zsh(Apple 的 5.9),而不是我们到处声明的 pkgs.zsh。
  #
  # 判据用"有没有显式写 uid":对**已存在**的账户,nix-darwin 不会重建,只会 dscl -create
  # 三样 —— PrimaryGroupID、RealName(description 非 null 时)、UserShell;但前提是
  # 配置里的 uid 和现有账户对得上,对不上它会打印 warning 然后整个跳过。所以 uid 是
  # 这件事唯一的安全阀,必须由 host 显式写出来,不能给默认值。
  #
  # 反向的风险 —— 哪天把某个用户从配置里删掉、而它还留在 knownUsers 里,nix-darwin
  # 会 dscl -delete 掉这个账户 —— 在 macOS 的首个用户身上够不着:它那条删除分支只对
  # uid > 501 的账户动手。(见 nix-darwin modules/users/default.nix。)
  darwinKnownUsers = lib.filter (n: (users.${n}.nixos or {}) ? uid) allUsers;
in {
  users =
    {
      users = lib.genAttrs allUsers mkUser;
    }
    // lib.optionalAttrs isDarwin {
      knownUsers = darwinKnownUsers;
    };
}
