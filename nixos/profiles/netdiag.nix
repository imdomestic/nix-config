# 路由/网关机上"人 ssh 进去查问题"需要的那几个工具。
#
# 抽出来之前,r5s / r5sjp / r6s / rpi4(以及已退役的 n100)各在自己的 host
# 文件里抄了一遍同一组包名,而且抄错了两处:
#
#   - `iproute2` 五处全是废话。NixOS 本来就把它放进了 system path(实测在
#     一个一行都没声明的 shanghai 上 `command -v ip` 照样解析到
#     iproute2/bin/ip)。
#   - `tailscale` 三处也是废话。`services.tailscale.enable` 自己会把 CLI
#     装进去,而这几台的 tailscale 是 modules/tailscale 按 my.host.tsIp 开的。
#
# 剩下这几个才是 NixOS 默认真的没有的(同一台 shanghai 上 tcpdump / ethtool /
# mtr 三个 `command -v` 全是 MISSING)。
#
# **故意不塞进 profiles/server.nix。** 那个是所有 server 都吃的,包括 tank /
# h610 / shanghai;它们不是路由器,平时也用不到 tcpdump。放这儿让"要它的机器
# 显式要"。
{pkgs, ...}: {
  environment.systemPackages = with pkgs; [
    # 抓包。排 dae/mihomo/xray 的问题基本都从这儿开始。
    tcpdump
    # 网卡状态、offload 开关、link 协商结果 —— 这几台是软路由,这些要看。
    ethtool
    # 路由 + 丢包一起看。和监控里的 ping_exporter 是同一类信息,但那个是
    # 长期趋势,这个是"现在立刻看一眼"。
    mtr
    # 不是网络工具,但这五台原本都装了它 —— 出问题时 ssh 进去改配置总得有个
    # 编辑器,而 NixOS 默认只给 nano。
    vim
  ];
}
