{lib, ...}: {
  imports = [
    ../modules/ssh
    # 采集端。模块自己按 my.host.tsIp 决定开不开,所以这里无条件 import ——
    # 没设 tsIp 的 server(aarch64-wsl/x470)会自动跳过。
    ../modules/telemetry
  ];

  services = {
    xserver.enable = lib.mkDefault false;
    printing.enable = lib.mkDefault false;
  };

  # 服务器上没人开浏览器看 NixOS 手册。实测 r6s 的闭包里 nixos-manual-html
  # 28 MiB、nix-manual 23 MiB、nix-doc 23 MiB —— 而这几台连桌面都没有,那个
  # HTML 手册连打开的方式都没有。
  #
  # **man page 故意留着**(documentation.man 不动):ssh 进去查 `man 5
  # systemd.network` 是这几台上真会发生的事,而它才几 MiB。
  documentation = {
    nixos.enable = lib.mkDefault false;
    doc.enable = lib.mkDefault false;
    info.enable = lib.mkDefault false;
  };

  # **cockpit 删了(2026-08-12)。** 在 NixOS 上它 15 个页面里大部分没有后端 ——
  # h610 上实测 pkcon / nmcli / udisksctl / sosreport / setenforce 全部 MISSING,
  # 于是 apps、packagekit、networkmanager、storaged、sosreport、selinux 六页
  # 全是死的。剩下能用的 shell / systemd / metrics 三页,这个 fleet 里分别有
  # ssh、node_exporter 的 systemd collector、和 Prometheus 做得更好。
  #
  # users 页更糟:全 fleet mutableUsers = true,在里面改一个 users.users 声明过
  # 的用户,下次 switch 会被静默改回去 —— 不报错,就是没了。这不是打包问题,是
  # 理念相反:cockpit 的前提是"用 GUI 改一台可变的机器",NixOS 的前提是"改配置
  # 再重建"。
  #
  # 实际使用情况也印证了:h610 和 r6s 早就各自 mkForce false 掉了,而还开着的
  # r5s / shanghai 三十天日志零条。
  #
  # 另外它是这个仓库"服务只绑 tailscale"这条规矩的唯一例外,而且三个最不该
  # 例外的选项凑齐了 —— openFirewall = true + allowed-origins = ["*"] +
  # AllowUnencrypted = true,实测监听在 [::]:9090(r5s 有 WAN + PPPoE,
  # shanghai 是公网 VPS,两台都 firewall.enable = false)。对比
  # modules/telemetry/default.nix:79 那条"绑定地址是唯一真正起作用的边界"。
  #
  # 顺带:Prometheus 当初为它让到 9009(见 modules/monitoring 的 port 选项),
  # 那个理由现在不成立了,但 9009 已经写进两份配置和看板,不值得再挪回去。

  # hardware.pulseaudio.enable = lib.mkDefault false;
  services.pipewire.enable = lib.mkDefault false;

  # Servers often rely on predictable networking
  networking.networkmanager.enable = lib.mkDefault false;
}
