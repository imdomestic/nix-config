{
  inputs,
  pkgs,
  lib,
  config,
  ...
}: let
  cfg = config.my.mihomo;
in {
  options.my.mihomo.smart = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      换成 vernesong 的 mihomo fork,它比上游多一个 `smart` 策略组。

      动机见 pkgs/mihomo-smart 里的注释:上游的 url-test 只看延迟,而实测
      h610 那条链路 RTT 89ms(看着完全健康)、吞吐只有 4.8 Mbit/s、丢包 13%,
      其余四个节点 63~146ms / 69~220 Mbit/s。任何按延迟选的策略都分辨不出
      这个差别,于是约 1/5 的流量被送进一条基本不可用的路。smart 组的评分
      同时看 latency 和 lossRate,后者取自内核 TCP_INFO 的 tcpi_total_retrans。

      **开这个选项只是换二进制,不会自动改选路行为** —— 还得把配置里对应的
      组类型从 url-test 改成 smart 才生效,而配置在另一个仓库
      (inputs.mihomo-config)。
    '';
  };

  config.services.mihomo = {
    enable = true;
    package = lib.mkIf cfg.smart (pkgs.callPackage ../../../pkgs/mihomo-smart {});
    tunMode = true;
    webui = pkgs.metacubexd;
    configFile = "${inputs.mihomo-config.outPath}/config.yaml";
  };
}
