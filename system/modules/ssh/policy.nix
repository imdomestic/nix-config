# How sshd authenticates, wherever it runs: keys only. On tailnet addresses
# port 22 belongs to Tailscale SSH (system/modules/tailscale), which never
# reaches sshd. The fleet's keys (./keys.nix) work for every account.
# Imported by system/profiles/base.nix; ./default.nix is what turns sshd on.
{lib, ...}: {
  environment.etc."ssh/authorized_keys.d/master" = {
    text = lib.concatStringsSep "\n" (import ./keys.nix);
    mode = "0444";
  };

  services.openssh.settings = {
    AuthorizedKeysFile = "%h/.ssh/authorized_keys /etc/ssh/authorized_keys.d/master";
    PasswordAuthentication = false;
    KbdInteractiveAuthentication = false;
    PermitRootLogin = "prohibit-password";
  };
}
