# deploy.nodes: every NixOS host with a tsName, with a `system` profile plus
# one `home-<account>` profile per account. Also `deployChecks`.
{
  config,
  inputs,
  lib,
  ...
}: let
  inherit (config.flake) nixosConfigurations homeConfigurations;

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

  deployable = lib.filterAttrs (_: h: h.tsName != null && h.kind == "nixos") config.hosts;

  # genAttrs 是逐属性惰性的,只有真正被部署用到的 system 才会去 import nixpkgs;
  # 按 system 收敛也避免了每台 host 各 import 一遍。
  deployLibs =
    lib.genAttrs (lib.unique (
      lib.mapAttrsToList (_: h: h.system) (lib.filterAttrs (_: h: h.tsName != null) config.hosts)
    ))
    mkDeployLib;

  # Homes are standalone closures (see ./homes.nix), so a system deploy does not
  # drag them along. Give every account of a deployable host its own profile
  # instead, otherwise accounts whose owner never logs in to run `home-manager`
  # themselves would silently stop being updated.
  mkHomeProfiles = name: host:
    lib.mapAttrs' (userName: _: {
      name = "home-${userName}";
      value = {
        user = userName;
        inherit (host) sshUser;
        # deploy-rs builds the activation command as `<sudo> <user> <script>`,
        # and its default `sudo -u` keeps the ssh user's HOME. Home Manager's
        # activation script resolves every path relative to $HOME, so without
        # -H it would write the user's home into /root.
        sudo = "sudo -H -u";
        # deploy-rs' own activate.home-manager, plus what `just hm` gets from
        # `-b backup`: a file Home Manager takes over for the first time is
        # moved to <name>.backup instead of failing the whole activation.
        path =
          deployLibs.${host.system}.activate.custom
          homeConfigurations."hosts/${name}/${userName}".activationPackage
          "HOME_MANAGER_BACKUP_EXT=backup $PROFILE/activate";
      };
    })
    host.users;

  # Deployment uses the same MagicDNS inventory as monitoring.
  nodes =
    lib.mapAttrs (name: host: let
      homeProfiles = mkHomeProfiles name host;
    in {
      hostname = host.tsName;

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
            inherit (host) sshUser;
            path = deployLibs.${host.system}.activate.nixos nixosConfigurations.${name};
          };
        }
        // homeProfiles;
    })
    deployable;
in {
  flake.deploy.nodes = nodes;

  # **每台一个 deploy check,而且放在 `deployChecks` 而不是 `checks`。**
  # 放 `checks` 里 `nix flake check` 会把它们全求值一遍,那会撑爆 CI runner
  # (见 docs/incidents.md#deploy-schema-timeout)。放在非标准输出上,nix 只会
  # 说一句 "unknown flake output" —— 已经在 ci.yml 的警告白名单里。
  #
  # 真正的验证在矩阵 job 里:那边每台本来就求值过自己的 toplevel,顺手验自己
  # 这一个节点几乎是白捡的,而且哪台坏了一眼看得出来。
  flake.deployChecks =
    builtins.mapAttrs
    (_system: deployLib:
      lib.concatMapAttrs
      (host: node:
        lib.mapAttrs'
        (name: check: lib.nameValuePair "${name}-${host}" check)
        (deployLib.deployChecks {nodes.${host} = node;}))
      nodes)
    inputs.deploy-rs.lib;
}
