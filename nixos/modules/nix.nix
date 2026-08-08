{inputs, ...}: {
  # The options below come from nixpkgs' config/nix-channel.nix and
  # config/nix-remote-build.nix, neither of which system-manager imports — hence
  # the split. system-manager hosts take nix-settings.nix on its own, which
  # carries the nix.conf settings and the registry pins.
  imports = [./nix-settings.nix];

  nixpkgs = {
    overlays = [
      inputs.nur.overlays.default
      inputs.nix-minecraft.overlay
      # inputs.headplane.overlays.default
      (final: prev: {
        zjstatus = inputs.zjstatus.packages.${prev.system}.default;
      })
    ];
    config = {
      allowUnfree = true;
    };
  };

  # nix.optimise.automatic = true;

  # nix.gc = {
  #   automatic = true;
  #   options = "--delete-older-than 1w";
  # };

  nix = {
    nixPath = [
      "nixpkgs=${inputs.nixpkgs}"
      "nixpkgs-unstable=${inputs.nixpkgs-unstable}"
    ];
    channel.enable = false;

    # 没有 buildMachines 了(见 lib/mkDeployNodes.nix 的 remoteBuild),留着它
    # 是惰性的 —— 万一以后手动往 /etc/nix/machines 里加东西,不用再打开一次。
    distributedBuilds = true;
  };
}
