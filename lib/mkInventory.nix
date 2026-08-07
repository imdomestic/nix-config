# 从 host registry 派生"被纳管的机器"这一份清单。
#
# 判据只有一条:`tsIp != null`。为什么不用 `roles` 或 `kind`:
#
# - 光看 roles 会把 b650/m16/gpd 这些 NixOS 桌面算进来,它们合盖就离线,
#   在监控里永远是 down,是告警噪声的主要来源。
# - 光看 kind 会漏掉 x470 这种双系统的坑:它 tailnet 上那个节点是 Windows
#   那份,NixOS 侧根本不在网里。
#
# tsIp 是"这台机器有一个稳定的、我能抓到它的地址"的直接证据,而不是间接推断。
# 加一台机器进监控 = 在 registry 里填一行 tsIp,采集端和抓取端同时生效。
#
# 返回一个 list 而不是 attrset:调用方基本都是拿去 map 成抓取目标/清单条目,
# 而且 attrset 的遍历顺序是按 key 排序的,输出稳定,diff 干净。
{inputs}: {hosts}: let
  lib = inputs.nixpkgs.lib;

  managed = lib.filterAttrs (_: h: (h.tsIp or null) != null) hosts;
in
  lib.mapAttrsToList (name: h: {
    inherit name;
    tsIp = h.tsIp;
    system = h.system;
    kind = h.kind or "nixos";
    roles = h.roles or [];
    # wireguard 那张网上的地址,可能没有(r5sjp 就没有)。这里带出来只是为了
    # 让 maxops 之后能在 tailscale 不通时有个回退目标可试,监控本身不用它。
    wgIp = h.ip or null;
  })
  managed
