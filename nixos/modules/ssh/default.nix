{lib, ...}: let
  keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINR7+B5jirLm5+cXrKabb0hrvq1OFxX6jCzKi/Sb4rkj ysh2291939848@outlook.com"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ/MFKoIlH1i0YDAnIoHQKmKEKFGcKa1V4gET/bYifcd ysh2291939848@outlook.com"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG290WBMVGWxpye7MliOTbiCZAd3mbi/Q9sFkBLE2Vno ysh2291939848@outlook.com"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILUdWAJA+GYaOtVHVkrvrEpwGpK//0hYdAYjYq/rzvtn ysh2291939848@outlook.com" # m1elite
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBY3nWjTRRfjPPtriUf6Ot5Qg83/3u2SA6ih8x5jrLYX ysh2291939848@outlook.com" # hackintosh
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAVka3wlxrH8v1fFxiTGxd8cnoAtbLyWDrb5xibOtDg4 linwhite@linwhite.top"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII6G+ioInToTcwGDI+Tnoq5/X/GpmEucCilJH6pkZOdJ 1823215739@qq.com" # fendada
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhXv+E5zF8pdF9SqxGMc21iAZYOuxPgP5rEx1DbtAsK 3526452465@qq.com" # kenneth
  ];
in {
  environment.etc."ssh/authorized_keys.d/master" = {
    text = lib.concatStringsSep "\n" keys;
    mode = "0444";
  };

  services.openssh = {
    enable = true;
    settings = {
      AuthorizedKeysFile = "%h/.ssh/authorized_keys /etc/ssh/authorized_keys.d/master";
      PasswordAuthentication = true;
      PermitRootLogin = "yes";
    };
  };

  # programs.ssh = {
  #   extraConfig = ''
  #     CanonicalizeHostname yes
  #     CanonicalizeMaxDots 0
  #     CanonicalDomains imdomestic.com
  #     CanonicalizeFallbackLocal no
  #     CanonicalizeFallbackLocal yes
  #   '';
  # };
}
