{
  inputs,
  usernames,
  system,
  ...
}: {
  nix.settings.trusted-users = usernames;
  nix.optimise.automatic = true;

  nix.gc = {
    automatic = true;
    options = "--delete-older-than 1w";
  };

  nixpkgs = {
    overlays = [
      inputs.nur.overlays.default
    ];
    config = {
      allowUnfree = true;
      allowUnfreePredicate = _: true;
      permittedInsecurePackages = [
        "electron-11.5.0"
      ];
    };
  };

  nix.settings = {
    substituters = [
      "https://cache.garnix.io"
      "https://cache.iog.io"
      "https://hyprland.cachix.org"
      "https://cache.nixos.org"
      "https://mirrors.ustc.edu.cn/nix-channels/store"
    ];
    trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "hyprland.cachix.org-1:a7pgxzMz7+chwVL3/pzj6jIBMioiJM7ypFP8PwtkuGc="
      "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
    ];
    experimental-features = ["nix-command" "flakes"];
  };
}
