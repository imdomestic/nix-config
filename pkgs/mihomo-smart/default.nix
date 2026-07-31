{
  lib,
  fetchFromGitHub,
  buildGoModule,
}:
# vernesong 的 mihomo fork。它比上游多一个 `smart` 策略组,那是我们要的唯一
# 东西 —— 上游 mihomo（以及 sing-box、dae、Surge 之外的几乎所有客户端）选路
# 只看延迟,而我们踩的坑恰恰是「延迟正常但吞吐崩溃」:
#
#   h610      RTT  89ms   吞吐 4.8 Mbit/s   丢包 13%
#   shanghai  RTT  63ms   吞吐 220 Mbit/s   丢包 0.31%
#
# 89ms 在任何延迟检查里都是健康的,所以 url-test / min_moving_avg 会一直把
# 流量往 h610 上送。smart 组的评分同时看 latency 和 lossRate,而 lossRate 在
# Linux 上取自内核 TCP_INFO 的 tcpi_total_retrans(component/smart/tcpstats/
# tcpstats_linux.go),这正是能把 h610 和其它节点区分开的量。
#
# 上游 mihomo 明确不打算做这件事:Clash Verge Rev 的 issue #7646 提了同样的
# 需求,维护者回复「Mihomo Core 印象中没有直接提供测量带宽的 API…我对此
# Issue 持否决态度」。所以只能走 fork。
buildGoModule rec {
  pname = "mihomo-smart";
  # 上游只发一个滚动的 `Prerelease-Alpha` tag,所以钉 commit 而不是 tag ——
  # 否则每次求值都可能拿到不同的代码。版本号取自它 merge 上游时的基线。
  version = "1.19.24-smart-unstable-2026-07-29";
  rev = "880847d582560df82ef7a36f858d42c8b64f7c66";

  src = fetchFromGitHub {
    owner = "vernesong";
    repo = "mihomo";
    inherit rev;
    hash = "sha256-oOmSq1v1yPuKnaEFyuF9wDW/Vs+H4eDBVbCflRhY7ng=";
  };

  vendorHash = "sha256-P8EO47MMTpHkB9xceYWdZXWA560FDPfmO8JDLdwPKgk=";

  excludedPackages = ["./test"];

  ldflags = [
    "-s"
    "-w"
    "-X github.com/metacubex/mihomo/constant.Version=${version}"
  ];

  tags = ["with_gvisor"];

  # 需要联网
  doCheck = false;

  meta = {
    description = "mihomo fork with the throughput/loss-aware `smart` policy group";
    homepage = "https://github.com/vernesong/mihomo";
    license = lib.licenses.gpl3Only;
    mainProgram = "mihomo";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
