# How sshd authenticates, wherever it runs: keys only. On tailnet addresses
# port 22 belongs to Tailscale SSH (system/modules/tailscale), which never
# reaches sshd. The fleet's keys (./keys.nix) work for every account.
# Imported by system/profiles/base.nix; ./default.nix is what turns sshd on.
{lib, ...}: {
  environment.etc."ssh/authorized_keys.d/master" = {
    text = lib.concatStringsSep "\n" (import ./keys.nix);
    mode = "0444";
  };

  # Appended to NixOS' own list (~/.ssh/authorized_keys, authorized_keys.d/%u),
  # not set in `settings`: settings render ahead of that list in sshd_config and
  # sshd keeps the first AuthorizedKeysFile, which hid every per-account key.
  services.openssh.authorizedKeysFiles = ["/etc/ssh/authorized_keys.d/master"];

  services.openssh.settings = {
    PasswordAuthentication = false;
    KbdInteractiveAuthentication = false;
    PermitRootLogin = "prohibit-password";
  };
}
