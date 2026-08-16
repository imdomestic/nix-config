# lib/mkDeployNodes.nix
{inputs}: {
  hosts,
  nixosConfigurations,
  homeConfigurations,
}: let
  inherit (inputs.nixpkgs) lib;

  # deploy-rs 上游**没有**自己的二进制缓存 —— 它的 flake 里没有 nixConfig,整个
  # 仓库也搜不到一处 cachix。而它又 follows 我们的 nixpkgs,于是 inputs.deploy-rs
  # 那个包是全世界没人构建过的 drv:每次部署都得在本地从 Rust 源码整编,连带拉
  # cargo/rustc/llvm 448 MiB。
  #
  # 解法是上游 README 自己给的那段:**留着 flake 的 lib,把二进制换成 nixpkgs 里
  # 那个**。`pkgs.deploy-rs` 是 Hydra 构建的,cache.nixos.org 里现成 —— 实测
  # 1.1 MiB 直接下,零编译。lib 仍取 flake 的,activate.* 的行为不变。
  #
  # 注意不能改成"去掉 follows 用它自己的 nixpkgs":那只是换成拿 deploy-rs pin 的
  # nixpkgs-unstable 去编,同样没人构建过,还白白多出一整个 nixpkgs 实例。
  mkDeployLib = system: let
    base = import inputs.nixpkgs {inherit system;};
  in
    (import inputs.nixpkgs {
      inherit system;
      overlays = [
        inputs.deploy-rs.overlays.default
        (_final: prev: {
          deploy-rs = {
            inherit (base) deploy-rs;
            inherit (prev.deploy-rs) lib;
          };
        })
      ];
    })
    .deploy-rs
    .lib;

  # genAttrs 是逐属性惰性的,只有真正被部署用到的 system 才会去 import nixpkgs;
  # 按 system 收敛也避免了每台 host 各 import 一遍。
  deployLibs =
    lib.genAttrs (lib.unique (
      lib.mapAttrsToList (_: h: h.system) (lib.filterAttrs (_: h: (h ? tsIp) && (h ? system)) hosts)
    ))
    mkDeployLib;

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
          deployLibs.${hostConfig.system}.activate.home-manager
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
  # 反过来,只有 `ip` 没有 tsIp 的 b650 / x470 就此不再是部署目标 ——
  # 这两台是桌面机,它们在 tailnet 里那个节点其实是各自的 Windows 那份。
  # 实测两台的 wg 地址也 ssh 不通,所以它们留在 deploy.nodes 里只是个
  # 一按就失败的空壳。它们照常有
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

        # **现在是在发起方构建**(commit 0645dfa 把 `remoteBuild = true;` 注释
        # 掉了,而 deploy-rs 的默认值就是 false)。后果:从 mac 部署任何 linux
        # 主机都要显式加 `--remote-build`,否则会尝试本地构建 x86_64-linux 然后
        # 失败。当初改成在目标机构建的实测理由(641 MiB 里 88% 目标机本来就有、
        # ARM 原生比 QEMU 快 3.7 倍)见 docs/incidents.md#deploy-remote-build,
        # 那条也记着这个矛盾。
        # remoteBuild = false;

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
              path = deployLibs.${hostConfig.system}.activate.nixos nixosConfigurations.${name};
            };
          }
          // homeProfiles;
      }
      else {}
  )
  (lib.filterAttrs (n: v: (v ? tsIp) && (v.kind or "nixos" == "nixos")) hosts)
