{
  inputs,
  pkgs,
  ...
}: {
  imports = [
    inputs.nixos-wsl.nixosModules.wsl
  ];

  wsl = {
    enable = true;
    defaultUser = "hank";
    useWindowsDriver = true;
    wslConf = {
      network.generateResolvConf = false;
      network.generateHosts = false;
    };
  };
  hardware.graphics.extraPackages = [
    (pkgs.runCommand "wsl-nvidia-symlink" {} ''
      mkdir -p $out/lib
      ln -s /usr/lib/wsl/lib/libnvidia-ml.so.1 $out/lib/libnvidia-ml.so
    '')
  ];
  programs.nix-ld.enable = true;
  environment.variables = {
    LD_LIBRARY_PATH = "/run/opengl-driver/lib:/usr/lib/wsl/lib";
  };

  networking.hostName = "wsl";
  networking.proxy.default = "http://127.0.0.1:7897";
  networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";
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
