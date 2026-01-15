{
  inputs,
  pkgs,
  ...
}: {
  boot.binfmt.emulatedSystems = ["aarch64-linux"];

  wsl = {
    enable = true;
    defaultUser = "hank";
    wslConf = {
      network.generateResolvConf = false;
      network.generateHosts = false;
    };
  };

  networking.hostName = "wsl";
  services.resolved.enable = true;

  time.timeZone = "Asia/Shanghai";

  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };

  security.sudo.wheelNeedsPassword = false;
  programs.zsh.enable = true;
  programs.nix-index-database.comma.enable = true;

  services.tailscale = {
    enable = true;
  };

  system.stateVersion = "25.11";
}
