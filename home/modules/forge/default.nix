{pkgs, ...}: let
  # The pinned nixpkgs package predates upstream's GNOME 50 compatibility fixes.
  forge = pkgs.gnomeExtensions.forge.overrideAttrs (oldAttrs: {
    version = "50-unstable-46736af";
    src = pkgs.fetchFromGitHub {
      owner = "forge-ext";
      repo = "forge";
      rev = "46736af63815b46cadeb1db2988f04d60e6601b8";
      hash = "sha256-bdoD5k33l0SwwuEmd+EvB0FiVJdbtIMeBrUAjRhSg2s=";
    };
    patches =
      (oldAttrs.patches or [])
      ++ [
        ./writable-stylesheet.patch
        ./keyboard-resize-boundary.patch
      ];
  });
in {
  programs.gnome-shell = {
    enable = true;
    extensions = [{package = forge;}];
  };
  dconf.settings."org/gnome/shell/extensions/forge".tiling-mode-enabled = true;
}
