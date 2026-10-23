# sshd on. How it authenticates is ./policy.nix, which every NixOS host gets.
{
  imports = [./policy.nix];

  services.openssh.enable = true;

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
