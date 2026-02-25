{lib, ...}: let
  keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINR7+B5jirLm5+cXrKabb0hrvq1OFxX6jCzKi/Sb4rkj ysh2291939848@outlook.com"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ/MFKoIlH1i0YDAnIoHQKmKEKFGcKa1V4gET/bYifcd ysh2291939848@outlook.com"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG290WBMVGWxpye7MliOTbiCZAd3mbi/Q9sFkBLE2Vno ysh2291939848@outlook.com"
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
