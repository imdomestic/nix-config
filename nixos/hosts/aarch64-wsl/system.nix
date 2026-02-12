{
  lib,
  pkgs,
  ...
}: {
  networking.hostName = "aarch64-wsl";
  wsl = {
    enable = true;
    defaultUser = "hank";
    wslConf = {
      network.generateResolvConf = false;
      network.generateHosts = false;
    };
  };

  networking.proxy.default = "http://127.0.0.1:7897";
  networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";
  time.timeZone = "Asia/Shanghai";

  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"];
    packages = with pkgs; [
      tree
    ];
  };
  security.sudo.wheelNeedsPassword = false;
  programs.zsh.enable = true;
  programs.nix-index-database.comma.enable = true;
  programs.nix-index = {
    enableBashIntegration = false;
    enableFishIntegration = false;
    enableZshIntegration = false;
  };
  programs.command-not-found.enable = false;

  environment.systemPackages = with pkgs; [
    kmod
    tzdata
    vim
    wget
    neovim
    git
    gcc
    starship
    zsh
    duf
    bat
    just

    distrobox
  ];

  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
    defaultNetwork.settings.dns_enabled = true;
  };

  services.resolved.enable = true;
  services.openssh.enable = true;
  services.tailscale = {
    enable = true;
  };

  system.stateVersion = "25.11";
  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";
}
