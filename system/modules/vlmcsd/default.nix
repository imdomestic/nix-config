{pkgs, ...}: let
  vlmcsd-pkg = pkgs.stdenv.mkDerivation rec {
    pname = "vlmcsd";
    version = "svn1113";

    src = pkgs.fetchFromGitHub {
      owner = "Wind4";
      repo = "vlmcsd";
      rev = "master";
      sha256 = "sha256-BEi47U0rdkO+AlQRpntsaTgm5A4CSwS6LuffAl2kIaw=";
    };

    nativeBuildInputs = [pkgs.gnumake pkgs.gcc];

    buildPhase = "make";

    installPhase = ''
      mkdir -p $out/bin
      cp bin/vlmcsd $out/bin/
      cp bin/vlmcs $out/bin/
    '';
  };
in {
  environment.systemPackages = [vlmcsd-pkg];

  systemd.services.vlmcsd = {
    description = "vlmcsd KMS Emulator Service";
    after = ["network.target" "tailscale.service"];
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      ExecStart = "${vlmcsd-pkg}/bin/vlmcsd -D -L 0.0.0.0:1688";
      Restart = "always";
      RestartSec = 5;
      DynamicUser = true;
    };
  };

  networking.firewall.allowedTCPPorts = [1688];
}
