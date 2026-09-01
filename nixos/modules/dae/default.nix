# dae 的完整配置。
#
# 原来这份配置整个躺在 `imdomestic/dae` 那个私有仓库里,通过 flake input 以
# `builtins.readFile` 读进来。搬到这里的理由:那 180 行里**唯一真正的秘密是
# 6 条节点 URI**(UUID + shortId 合起来才是凭据),其余全是路由规则。为了这
# 6 行单独维护一个私有仓库不划算,而且那样一来:
#
#   - 路由规则改一次要动两个仓库,还要 `nix flake lock --update-input`
#   - 规则本身没有秘密,却跟着一起被藏起来,评审和 grep 都不方便
#   - 三台机器读同一个文件,想给某台单独改 lan_interface 只能做字符串替换
#
# 现在:规则在 nix 里明文可读可评审,凭据走 sops(`dae/nodes`),渲染出的
# 配置落在 /run/secrets 而不是 world-readable 的 nix store。
#
# ---------------------------------------------------------------------------
# 为什么用 configFile 而不是 services.dae.config:
#
# `config` 是把内容写进 nix store 的,那是 world-readable 的 —— 节点 URI 进
# store 等于凭据对本机所有用户可读。configFile 指向 sops 渲染出来的文件
# (/run/secrets/rendered/,0400 root),这也是本仓库 cliproxy / ddns-go /
# xray 一贯的做法。
#
# 两个 dae 自己的硬性要求,踩过:
#   - 文件名必须以 `.dae` 结尾,否则报 "invalid config filename"。
#   - 权限不能对 group 可写、不能对 others 可读,否则报 "permissions ...
#     are too open"。sops 模板默认 0400 root,正好满足。
# ---------------------------------------------------------------------------
{
  pkgs,
  lib,
  config,
  ...
}: let
  cfg = config.my.dae;
in {
  options.my.dae.lanInterfaces = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = ["br-lan"];
    example = ["br-lan" "tailscale0"];
    description = ''
      dae 的 `lan_interface` —— 决定哪些网卡上的**转发**流量会被透明代理。

      shanghai 要当 tailscale exit node,所以那台要把 `tailscale0` 也算进来:
      exit node 的流量是从 tailscale0 进来再转发出去的,不在这个列表里 dae
      根本看不到,会直接从 WAN 裸奔出网 —— 结果是能上网但完全没走分流,
      而且这个失败是静默的。

      h610 和 rpi4 保持默认:它们不是 exit node,没有 tailscale 转发流量。
    '';
  };

  config = {
    # 节点 URI。
    #
    # **必须显式指定 sopsFile。** profiles/base.nix 把 defaultSopsFile 设成了
    # secrets/hosts/<host>.yaml(存在的话),而这份节点清单是几台 dae 主机共用的,
    # 放在共享的 secrets/secrets.yaml 里。不写这行的话 sops-install-secrets 会
    # 去每主机文件里找,构建时报 "the key 'dae' cannot be found"。
    #
    # 加解密范围见 .sops.yaml 的 `secrets/.*\.yaml$` 那条 —— 覆盖全部 17 个
    # 收件人,包括重新启用的 host_r2s 和 2026-08-16 加入的 host_h310。
    #
    # **往这个文件加收件人之后必须跑 `sops updatekeys secrets/secrets.yaml`。**
    # 改 .sops.yaml 只影响之后新建的文件,已加密的那份不会自动重新加密 ——
    # 漏了这步,新机器上 sops-install-secrets 会在激活阶段才报解不开。
    sops.secrets."dae/nodes".sopsFile = ../../../secrets/secrets.yaml;

    sops.templates."dae.dae" = {
      restartUnits = ["dae.service"];
      content = ''
        global {
            lan_interface: ${lib.concatStringsSep ", " cfg.lanInterfaces}
            wan_interface: auto
            log_level: info
            allow_insecure: false
            auto_config_kernel_parameter: true

            # --- 存活检查 ---
            # 检查目标都带上兜底 IP，避免“检查目标的 DNS 解析又绕回 im 组”造成死锁，
            # 从而出现所有节点被同时判死(no alive dialer)。检查是直接经节点发起的，
            # 不受下面 routing 规则影响，所以这里给的目标必须是经 r5sjp 出口能访问到的。
            tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
            tcp_check_http_method: HEAD
            # 反向代理(portal/bridge)对 UDP 支持差，UDP 检查可能一直失败；
            # 用国内可达的 alidns，并给定显式 IP 避免 UDP 检查再去解析域名，
            # UDP 不通只影响 UDP 流量、不连累 TCP。
            udp_check_dns: 'dns.alidns.com:53,223.5.5.5'
            check_interval: 30s
            # 容差，避免节点延迟轻微波动就来回切换/抖动判死
            check_tolerance: 100ms
        }

        node {
            # imdomestic-* —— 五台 portal 的 client-in2(54322),经反向隧道从
            # r5sjp 出去(日本)。au-* —— 同样两台 portal 的 client-au(54324),
            # 经反向隧道从 rpi4 出去(悉尼)。
            # 内容来自 sops(dae/nodes),不进 nix store。
        ${config.sops.placeholder."dae/nodes"}
        }

        dns {
            upstream {
                googledns: 'tcp+udp://dns.google.com:53'
                alidns: 'udp://dns.alidns.com:53'
                txdns: 'udp://119.29.29.29:53'
                # txdns: 'https://doh.pub/dns-query:443'
            }
            routing {
                # 根据DNS查询的请求，决定使用哪个DNS服务器
                # 规则从上到下匹配
                request {
                    # 全匹配和正则匹配
                    # qname(full: ok.com, regex: '^yes') -> googledns
                    # 内置出站:asis,reject
                    # 可用的方法 qname, qtype
                    # 广告拒绝
                    qname(geosite:category-ads-all) -> reject
                    # 这里的意思是google中是cn的域名使用alidns
                    qname(geosite:google@cn, geosite:cn, geosite:private, geosite: apple@cn) -> alidns
                    # 匹配后缀，匹配关键字
                    # qname(suffix: abc.com, keyword: google) -> googledns
                    # qname(geosite:geolocation-!cn, keyword: bing) -> googledns

                    # DNS 请求类型
                    # ipv4和ipv6请求使用alidns
                    # qtype(a, aaaa) -> alidns
                    # cname请求googledns
                    # qtype(cname) -> googledns
                    # 默认DNS服务器
                    fallback: alidns
                }

                # 根据DNS查询的响应，决定接受或者使用另外一个DNS服务器重新查询记录
                # 规则从上到下匹配

                response {
                    # 内置出站：accept,reject
                    # 可用的方法：qname, qtype, upstream, ip.
                    # 如果是发送到googledns的请求响应，则接受，可用于避免循环

                    upstream(googledns) -> accept
                    # 意思是如果请求的域名不是国内网站，但是返回了一个私有的IP，那就是被污染了。重新通过googledns请求
                    ip(geoip:private) && !qname(geosite:cn) -> googledns

                    # 以上不匹配，默认
                    fallback: accept
                }
            }
        }

        group {
            im {
                filter: name(keyword: 'imdomestic')
                policy: min_moving_avg
            }

            # 悉尼出口。**节点名故意不含 "imdomestic"** —— 上面 im 组是按关键字
            # 筛的,一旦叫成 imdomestic-*-au 就会被收进去,而 min_moving_avg 只看
            # 延迟:悉尼延迟更低、带宽却只有日本的约 1/9(实测 21 vs 187 Mbps),
            # 于是它会稳定当选然后把一切拖垮。
            #
            # 下面 routing 里没有任何规则指向 au,它现在是备着的 —— 要用就加一条
            # 形如 `domain(suffix: example.com) -> au`。留着组是为了让存活检查一直
            # 跑,真要用的时候不必先排查隧道通不通。
            au {
                filter: name(keyword: 'au-')
                policy: min_moving_avg
            }
        }

        routing {
            #tailscale
            dip(100.100.100.100) -> must_direct
            sport(41641) -> must_direct
            dport(41641) -> must_direct
            dip(100.64.0.0/10) -> must_direct
            dip('fd7a:115c:a1e0::/48') -> must_direct
            pname(tailscaled) -> must_direct
            pname(tailscale) -> must_direct

            # 去自建基础设施的连接一律直连。没有这条的话，routing 末尾的
            # `fallback: im` 会把 SSH 到 <host>.imdomestic.com 也丢进 im 组，而 im 组
            # 本身就是经 portal -> 反向隧道 -> r5sjp。于是隧道一断，用来修隧道的 SSH
            # 也跟着断，没法回滚。自己的机器本来也不需要走代理才能到达。
            # (原先只有 tailscale.imdomestic.com 一条，已被这条 suffix 规则覆盖。)
            domain(suffix: imdomestic.com) -> must_direct

            dip(223.5.5.5/32) -> direct
            dip(223.6.6.6/32) -> direct
            dip(119.29.29.29/32) -> direct
            dip(224.0.0.0/4, 'ff00::/8') -> direct

            dip(geoip:private) -> direct

            pname(qbittorrent, qq, wechat) -> direct
            pname(git) -> im
            domain(suffix: qq.com, full: woshicver.com, geosite:category-companies@cn) -> direct
            domain(
                geosite:category-game-platforms-download@cn,
                geosite:category-games-cn,
                geosite:steam@cn,
                suffix: cm.steampowered.com,
                suffix: steamserver.net
            ) -> direct
            dip(
                45.121.184.0/24,
                103.10.124.0/23,
                103.28.54.0/24,
                146.66.152.0/24,
                146.66.155.0/24,
                153.254.86.0/24,
                155.133.224.0/22,
                155.133.230.0/24,
                155.133.232.0/23,
                155.133.234.0/24,
                155.133.236.0/22,
                155.133.240.0/23,
                155.133.244.0/23,
                155.133.246.0/24,
                155.133.248.0/21,
                162.254.192.0/21,
                185.25.182.0/23,
                190.217.32.0/22,
                192.69.96.0/22,
                205.196.6.0/24,
                208.64.200.0/22,
                208.78.164.0/22,
                205.185.194.0/24
            ) -> direct
            dip(8.8.8.8) -> im

            domain(geosite:cn) -> direct
            dip(geoip:cn) -> direct

            domain(geosite:bilibili) -> direct

            domain(suffix:cm.steampowered.com) -> direct
            domain(suffix:steamserver.net) -> direct
            domain(suffix:steamcontent.com) -> direct
            domain(geosite:steam@cn) -> direct
            domain(geosite:steam) -> im

            domain(geosite:epicgames) -> direct
            domain(geosite:ea) -> direct
            domain(geosite:ubisoft) -> direct

            domain(geosite:apple@cn) -> direct
            domain(geosite:apple) -> direct

            domain(geosite:github) -> im

            domain(geosite:microsoft) -> direct

            domain(geosite:category-ads-all) -> block

            # ipversion(6) && domain(geosite:discord) -> block
            domain(geosite:discord) -> im

            domain(geosite:google-gemini) -> im
            domain(geosite:google) -> im

            domain(geosite:telegram) -> im

            fallback: im
        }
      '';
    };

    services.dae = {
      enable = true;
      package = pkgs.dae;
      configFile = config.sops.templates."dae.dae".path;
      assets = with pkgs; [v2ray-geoip v2ray-domain-list-community];
    };
  };
}
