# 自用节点的唯一真相 —— modules/{imsub,mihomo,singbox} 三处共用这一份。
#
# 以前这份名单在那三个模块里各抄了一遍。加一台机器要改三处,少改一处**不会
# 报错**,只会静悄悄地少一个节点(r2s 上线时两处都漏过)。2026-09-01 加澳洲
# 出口时三处必须同改,顺手收编成这一个文件。
#
# 四个字段各有各的理由,不能压成一个字符串:
#
#   name   客户端里看到的节点名后缀(imsub/mihomo 用 `imdomestic-<name>`,
#          singbox 用 `im-<name>`)。
#   host   DNS 名。**au 节点和它对应的本土节点是同一台机器、同一个域名**,
#          只有端口不同 —— 所以 host 推不出 name,反之亦然。
#   port   54322 = client-in2,流量经反向隧道从 r5sjp(日本)出去。
#          54324 = client-au,经反向隧道从 rpi4(悉尼)出去。
#   secret secrets/clients/imdomestic.yaml 里的键名。
#   exit   这个节点最终从哪儿出网:"jp" = r5sjp,"au" = rpi4。**只有它决定
#          节点进不进自动测速组** —— 别拿 port 或名字里的 "-au" 去判断。
#
# 悉尼那条出口带宽只有日本的约 1/9(实测 21 vs 187 Mbps),所以两个 au 节点
# 只进「手动选择」的策略组,绝不能进 urltest/auto 这类自动组 —— 详见
# docs/decisions.md#au-exit-not-in-auto-group。
[
  {
    name = "h610";
    host = "h610.imdomestic.com";
    port = 54322;
    secret = "h610";
    exit = "jp";
  }
  {
    name = "sh";
    host = "sh.imdomestic.com";
    port = 54322;
    secret = "sh";
    exit = "jp";
  }
  {
    name = "r5s";
    host = "r5s.imdomestic.com";
    port = 54322;
    secret = "r5s";
    exit = "jp";
  }
  {
    name = "r6s";
    host = "r6s.imdomestic.com";
    port = 54322;
    secret = "r6s";
    exit = "jp";
  }
  {
    name = "r2s";
    host = "r2s.imdomestic.com";
    port = 54322;
    secret = "r2s";
    exit = "jp";
  }

  # 悉尼出口。只有 h610 和 sh 两台 —— 其余几台 portal 的 DDNS 只发 AAAA,
  # 而悉尼那条线没有 IPv6,rpi4 的 bridge 根本拨不过去。
  {
    name = "h610-au";
    host = "h610.imdomestic.com";
    port = 54324;
    secret = "h610-au";
    exit = "au";
  }
  {
    name = "sh-au";
    host = "sh.imdomestic.com";
    port = 54324;
    secret = "sh-au";
    exit = "au";
  }
]
