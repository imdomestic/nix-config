# lib/mkDeployNodes.nix
{inputs}: {
  hosts,
  nixosConfigurations,
  homeConfigurations,
}: let
  inherit (inputs.nixpkgs) lib;
  deploy-rs = inputs.deploy-rs;

  # Homes are standalone closures now (see lib/mkConfigurations.nix), so a
  # system deploy no longer drags them along. Give every user of a deployable
  # host their own profile instead, otherwise accounts whose owner never logs in
  # to run `home-manager` themselves would silently stop being updated.
  mkHomeProfiles = name: hostConfig: let
    sshUser = hostConfig.sshUser or "root";
    mkProfile = userName: _: {
      name = "home-${userName}";
      value = {
        user = userName;
        inherit sshUser;
        # deploy-rs builds the activation command as `<sudo> <user> <script>`,
        # and its default `sudo -u` keeps the ssh user's HOME. Home Manager's
        # activation script resolves every path relative to $HOME, so without
        # -H it would write the user's home into /root.
        sudo = "sudo -H -u";
        path =
          deploy-rs.lib.${hostConfig.system}.activate.home-manager
          homeConfigurations."hosts/${name}/${userName}";
      };
    };
  in
    lib.mapAttrs' mkProfile (hostConfig.users or {});
  # **部署一律走 tailscale 地址,`my.host.tsIp` 就是可部署的判据。**
  #
  # 为什么不是 `ip`(wireguard 的 10.0.0.x):
  #
  #   - **r5sjp 和 r2s 只有 tailscale 地址。** 按 `ip` 过滤的话这两台压根不在
  #     deploy.nodes 里,根本没法部署 —— 而 r5sjp 是整条代理链唯一的出口,
  #     docs/proxy-todo.md 里也写明了它只能经 100.64.0.16 访问。
  #   - tailnet 到哪都通,不需要人先接进 wg;headscale 的 ACL 已经把这四个人
  #     圈好了。
  #   - 实测到 tank 两条路延迟相当(wg 30ms / ts 32ms),换过去不吃亏。
  #
  # 反过来,只有 `ip` 没有 tsIp 的 b650 / n100 / x470 就此不再是部署目标 ——
  # 这三台是桌面机,b650 和 x470 在 tailnet 里那个节点其实是它们的 Windows
  # 那份,n100 压根没开 tailscale。实测三台的 wg 地址也全都 ssh 不通,所以
  # 它们留在 deploy.nodes 里只是个一按就失败的空壳。它们照常有
  # nixosConfigurations,本机 `just switch` 不受影响。
  #
  # 加一台新机器进部署范围 = 在 registry 里填一行 tsIp,和监控是同一个开关。
in
  lib.mapAttrs (
    name: hostConfig: let
      isDeployable = (hostConfig ? tsIp) && (builtins.hasAttr name nixosConfigurations);
      homeProfiles = mkHomeProfiles name hostConfig;
    in
      if isDeployable
      then {
        hostname = hostConfig.tsIp;

        fastConnection = false;
        autoRollback = true;
        magicRollback = true;
        activationTimeout = 120;

        # System first: a home generation may reference users, groups or
        # services the new system introduces.
        profilesOrder = ["system"] ++ lib.attrNames homeProfiles;

        profiles =
          {
            system = {
              user = "root";
              sshUser = hostConfig.sshUser or "root";
              path = deploy-rs.lib.${hostConfig.system}.activate.nixos nixosConfigurations.${name};
            };
          }
          // homeProfiles;
      }
      else {}
  )
  (lib.filterAttrs (n: v: (v ? tsIp) && (v.kind or "nixos" == "nixos")) hosts)
