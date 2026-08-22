{
  lib,
  pkgs,
  ...
}: {
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
  time.timeZone = "Asia/Hong_Kong";

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

  # 其余的都搬去了 home:wget/starship/zsh/duf/bat/just 在 profiles/base.nix,
  # git 是 hank 自己的 programs.git,neovim 是 nixvim,gcc 在 profiles/dev.nix,
  # distrobox 挂在 users/hank 的 host 条件里。
  environment.systemPackages = with pkgs; [
    kmod
    tzdata
    # 系统坏掉时是以 root 身份进来修的,那时候 home 的 PATH 帮不上忙。
    vim
  ];

  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
    defaultNetwork.settings.dns_enabled = true;
  };

  services.resolved = {
    enable = true;
    settings.Resolve.FallbackDNS = ["223.5.5.5"];
  };
  services.openssh.enable = true;
  # 没有 tsIp(不是部署目标),所以要显式开。见 nixos/modules/tailscale。
  my.tailscale.enable = true;

  system.stateVersion = "25.11";
  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";
}
