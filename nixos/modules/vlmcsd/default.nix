{ pkgs, ... }:

let
  # 定义自定义的 vlmcsd 软件包
  vlmcsd-pkg = pkgs.stdenv.mkDerivation rec {
    pname = "vlmcsd";
    version = "svn1113";

    src = pkgs.fetchFromGitHub {
      owner = "Wind4";
      repo = "vlmcsd";
      rev = "master";
      # 这是目前的正确哈希值（针对 aarch64 源码）
      sha256 = "sha256-BEi47U0rdkO+AlQRpntsaTgm5A4CSwS6LuffAl2kIaw="; 
    };

    nativeBuildInputs = [ pkgs.gnumake pkgs.gcc ];

    buildPhase = "make";

    installPhase = ''
      mkdir -p $out/bin
      cp bin/vlmcsd $out/bin/
      cp bin/vlmcs $out/bin/
    '';
  };
in
{
  # 将编译好的包加入系统环境
  environment.systemPackages = [ vlmcsd-pkg ];

  # 配置 Systemd 服务
  systemd.services.vlmcsd = {
    description = "vlmcsd KMS Emulator Service";
    after = [ "network.target" "tailscale.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${vlmcsd-pkg}/bin/vlmcsd -D -L 0.0.0.0:1688";
      Restart = "always";
      RestartSec = 5;
      DynamicUser = true;
    };
  };

  # 开放端口
  networking.firewall.allowedTCPPorts = [ 1688 ];
}
