{lib, ...}: let
  keys = import ./keys.nix;
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
