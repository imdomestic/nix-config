{pkgs, ...}: let
  forwardingSecret = "hbhbhb";
  secretFile = pkgs.runCommand "forwarding.secret" {} "echo -n '${forwardingSecret}' > $out";
in {
  imports = [
    ./gate.nix
  ];

  # services.minecraft-servers = {
  #   enable = false;
  #   eula = true;
  # };
}
