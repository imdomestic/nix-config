{
  lib,
  pkgs,
  ...
}: {
  # Droidspaces supplies the kernel, namespaces, root filesystem and PID 1.
  # NixOS must not install or manage a boot loader in this environment.
  boot.isContainer = true;

  # Droidspaces' seccomp/container boundary lets individual namespaces work,
  # but not the namespace combination Nix uses for Linux build sandboxes.
  nix.settings.sandbox = true;

  # The stock Droidspaces image ships /sbin/init as a regular script pinned to
  # the image's original store path. Keep the runtime entry point following the
  # active NixOS system profile after every rebuild.
  system.activationScripts.droidspacesInit.text = ''
    ln -sfn /nix/var/nix/profiles/system/init /sbin/init
  '';

  # The container shares Android's network namespace. In particular, do not
  # let NixOS rewrite the phone's firewall rules or manage its interfaces.
  networking = {
    useDHCP = false;
    useHostResolvConf = true;
    firewall.enable = false;
  };

  time.timeZone = "Asia/Shanghai";
  i18n.defaultLocale = "en_US.UTF-8";

  security.sudo.wheelNeedsPassword = false;
  programs.zsh.enable = true;

  environment.systemPackages = with pkgs; [
    git
    vim
  ];

  # Android's recovery sshd remains on 2222; this is the native NixOS sshd.
  services.openssh = {
    ports = [22];
    openFirewall = false;
    settings = {
      PasswordAuthentication = lib.mkForce false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = lib.mkForce "prohibit-password";
    };
  };

  system.stateVersion = "26.05";
}
