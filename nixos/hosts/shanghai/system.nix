{pkgs, ...}: {
  imports = [
    ./hardware-configuration.nix
    ../../modules/dae
  ];

  networking.hostName = "shanghai";
  networking.domain = "";
  time.timeZone = "Asia/Shanghai";

  boot.loader.grub.enable = true;
  boot.loader.grub.useOSProber = false;
  boot.tmp.cleanOnBoot = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };
  zramSwap.enable = true;

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

  networking = {
    firewall.enable = false;
    networkmanager.enable = false;
    useNetworkd = true;
    useDHCP = false;
    nftables = {
      enable = true;
    };
  };

  systemd.network = {
    enable = true;
    netdevs."10-br-lan" = {
      netdevConfig = {
        Kind = "bridge";
        Name = "br-lan";
      };
    };

    networks."20-lan-uplink" = {
      matchConfig.Name = "ens5";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."30-br-lan" = {
      matchConfig.Name = "br-lan";
      networkConfig = {
        DHCP = "yes";
        IPv6AcceptRA = true;
      };
      linkConfig = {
        RequiredForOnline = "routable";
      };
    };
  };

  services.resolved.enable = true;
  services.qemuGuest.enable = true;

  services.iperf3.enable = true;
  services.openssh.enable = true;
  services.openssh.openFirewall = true;
  services.openssh.settings = {
    PasswordAuthentication = true;
    PermitRootLogin = "yes";
  };

  security.sudo.wheelNeedsPassword = false;

  environment.systemPackages = with pkgs; [
    git
    neovim
    fzf
  ];
  environment.pathsToLink = ["/share/applications" "/share/xdg-desktop-portal"];

  programs.zsh.enable = true;
  system.stateVersion = "25.11";
}
