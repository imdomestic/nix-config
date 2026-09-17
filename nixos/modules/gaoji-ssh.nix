{config, lib, ...}: let
  user = config.services.gaoji-host-control.ssh.user;
  port = 2224;
in {
  services.gaoji-host-control.ssh = {
    enable = true;
    authorizedKeys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFi0gZ1hnD8MSHQljzBzrezVYbLrNMHMZxnPRGcwUh3u gaoji-operations"];
  };

  # Keep ordinary SSH listeners; this port avoids Tailscale SSH interception.
  services.openssh.listenAddresses = lib.mkAfter [
    {addr = "0.0.0.0";}
    {addr = "[::]";}
    {addr = "0.0.0.0"; inherit port;}
    {addr = "[::]"; inherit port;}
  ];
  services.openssh.extraConfig = ''
    Match LocalPort ${toString port}
      AllowUsers ${user}
      AuthenticationMethods publickey
      PasswordAuthentication no
      KbdInteractiveAuthentication no
    Match User ${user}
      AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u
      AuthenticationMethods publickey
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      DisableForwarding yes
      PermitTTY no
      ForceCommand /run/wrappers/bin/sudo -n -- /run/current-system/sw/bin/gaoji-ssh-operations
    Match all
  '';
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [port];
}
