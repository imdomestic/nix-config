{
  inputs,
  usernames,
  system,
  ...
}: {
  nix.settings.trusted-users = usernames;
  # nix.optimise.automatic = true;

  # nix.gc = {
  #   automatic = true;
  #   options = "--delete-older-than 1w";
  # };

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

  nix = {
    registry = {
      nixpkgs.flake = inputs.nixpkgs;
      nixpkgs-local.flake = inputs.nixpkgs;
      nixpkgs-unstable.flake = inputs.nixpkgs-unstable;
    };
    nixPath = [
      "nixpkgs=${inputs.nixpkgs}"
      "nixpkgs-unstable=${inputs.nixpkgs-unstable}"
    ];
    channel.enable = false;
    distributedBuilds = true;
  };

  # nix.buildMachines = [
  #   {
  #     hostName = "tank";
  #     system = "x86_64-linux";
  #     maxJobs = 20;
  #     speedFactor = 2;
  #     supportedFeatures = ["nixos-test" "benchmark" "big-parallel" "kvm"];
  #   }
  # ];

  nix.settings = {
    # 数字越小越优先:SJTU 镜像加速 -> 官方源兜底 -> 其余专用 cache
    substituters = [
      "https://mirror.sjtu.edu.cn/nix-channels/store?priority=10"
      "https://cache.nixos.org?priority=20"
      "https://cache.garnix.io?priority=30"
      "https://cache.iog.io?priority=40"
      "https://cache.nixos-cuda.org?priority=50"
    ];
    trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
      "cache.nixos-cuda.org:74DUi4Ye579gUqzH4ziL9IyiJBlDpMRn9MBN8oNan9M="
    ];
    experimental-features = ["nix-command" "flakes"];
    allow-import-from-derivation = true;
  };
}
