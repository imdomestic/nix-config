{
  lib,
  pkgs-unstable,
  ...
}: {
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

  services.cockpit = {
    package = pkgs-unstable.cockpit;
    enable = true;
    port = 9090;
    openFirewall = true;
    allowed-origins = ["*"];
    settings = {
      WebService = {
        AllowUnencrypted = true;
      };
    };
  };

  # hardware.pulseaudio.enable = lib.mkDefault false;
  services.pipewire.enable = lib.mkDefault false;

  # Servers often rely on predictable networking
  networking.networkmanager.enable = lib.mkDefault false;
}
