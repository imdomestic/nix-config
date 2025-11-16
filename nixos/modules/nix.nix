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
      # inputs.niri.overlays.niri
    ];
    config = {
      allowUnfree = true;
      allowUnfreePredicate = _: true;
      permittedInsecurePackages = [
        "electron-11.5.0"
        "mbedtls-2.28.10"
      ];
    };
  };

  nix.settings = {
    substituters = [
      "https://mirrors.ustc.edu.cn/nix-channels/store"
      "https://cache.garnix.io"
      "https://cache.iog.io"
      "https://hyprland.cachix.org"
      "https://mirror.sjtu.edu.cn/nix-channels/store"
    ];
    trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "hyprland.cachix.org-1:a7pgxzMz7+chwVL3/pzj6jIBMioiJM7ypFP8PwtkuGc="
      "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
    ];
    experimental-features = ["nix-command" "flakes"];
  };
}
