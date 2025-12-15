{pkgs, ...}: {
  imports = [
    ./hardware-configuration.nix
  ];

  networking.hostName = "shanghai";
  time.timeZone = "Asia/Shanghai";

  boot.loader.grub.enable = true;
  boot.loader.grub.useOSProber = false;

  networking.useNetworkd = true;
  systemd.network.enable = true;
  networking.useDHCP = false;
  networking.interfaces.ens5.useDHCP = true;

  services.resolved.enable = true;
  services.qemuGuest.enable = true;

  services.openssh.enable = true;
  services.openssh.openFirewall = true;
  services.openssh.settings = {
    PasswordAuthentication = true;
    PermitRootLogin = "yes";
  };

  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDgKVrXIcm6y0r6KWHSBCNfftsShgy/dTdkQBo4YNuZjq0fxd/AtxZRELfFFuJbA5OaT6XZPLvf6c9gh9wrUGY1gdW1qhtDEgvlmGFH05cxgDlktw0BqLWxqjvdyjUvPn+oA526YjhjD8bK4zTPQQ9B0MNUQuY8UGg1VHD+0drgLYZQolqOxRUL15R1aBqEOl885j8pSEGacTv9mDGEZxBhQZKAauo1WN38vPH6Diq8zBz652jNaHedNdHd3zRqXRUGjHLTnKY5Jq7rvAnHdGZlH2STtu4BhLxOEVd6p28VRsLpeuMnz9xpVbgMmiTZvKlj2AFtk2qM8Sb9kHxgSEVTo+w83Rkn18DYinhfgWCP4ikqGs1Q5kgO1O7F32kFngqW0IPRadYtIGE2JHhRPuEzeubETZJQX4AKDYOIFpxXbcK1jBM+rDnhLmfsJh5nC9U/ZP7C6LN+BJuEwhDutK2EGZVC1oZ4cYgnL3V0ip5Ics4i/o2RTk8s5ETdbd/bU1E= ysh2291939848@outlook.com"
  ];

  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"];
    openssh.authorizedKeys.keys = [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDgKVrXIcm6y0r6KWHSBCNfftsShgy/dTdkQBo4YNuZjq0fxd/AtxZRELfFFuJbA5OaT6XZPLvf6c9gh9wrUGY1gdW1qhtDEgvlmGFH05cxgDlktw0BqLWxqjvdyjUvPn+oA526YjhjD8bK4zTPQQ9B0MNUQuY8UGg1VHD+0drgLYZQolqOxRUL15R1aBqEOl885j8pSEGacTv9mDGEZxBhQZKAauo1WN38vPH6Diq8zBz652jNaHedNdHd3zRqXRUGjHLTnKY5Jq7rvAnHdGZlH2STtu4BhLxOEVd6p28VRsLpeuMnz9xpVbgMmiTZvKlj2AFtk2qM8Sb9kHxgSEVTo+w83Rkn18DYinhfgWCP4ikqGs1Q5kgO1O7F32kFngqW0IPRadYtIGE2JHhRPuEzeubETZJQX4AKDYOIFpxXbcK1jBM+rDnhLmfsJh5nC9U/ZP7C6LN+BJuEwhDutK2EGZVC1oZ4cYgnL3V0ip5Ics4i/o2RTk8s5ETdbd/bU1E= ysh2291939848@outlook.com"
    ];
  };

  nix.settings = {
    substituters = [
      "https://mirrors.ustc.edu.cn/nix-channels/store?priority=10"
      "https://mirror.sjtu.edu.cn/nix-channels/store?priority=20"
      "https://cache.nixos.org?priority=40"
    ];
    trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    ];
  };
  boot.tmp.cleanOnBoot = true;
  zramSwap.enable = true;
  networking.domain = "";
  environment.systemPackages = with pkgs; [
    git
    neovim
    fzf
  ];
  system.stateVersion = "23.11";
}
