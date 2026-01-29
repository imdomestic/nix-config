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
    ];
    config = {
      allowUnfree = true;
    };
  };

  nix = {
    registry = {
      nixpkgs.flake = inputs.nixpkgs;
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
    substituters = [
      "https://mirrors.ustc.edu.cn/nix-channels/store"
      "https://cache.garnix.io"
      "https://cache.iog.io"
      "https://mirror.sjtu.edu.cn/nix-channels/store"
      "https://cache.nixos-cuda.org"
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
