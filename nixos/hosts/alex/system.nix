{
  config,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/nerdfonts
  ];

  system.stateVersion = 5;
  nixpkgs.hostPlatform = "aarch64-darwin";

  networking.computerName = config.my.host.name;
  system.defaults.smb.NetBIOSName = config.my.host.name;
  system.primaryUser = "kenneth";

  # The only installed cask is font-fira-code. Install both font families
  # through nix-darwin instead; the command-line formulae live in Kenneth's
  # standalone Home Manager closure.
  fonts.packages = with pkgs; [
    fira-code
    recursive
  ];

  programs.nix-index-database.comma.enable = true;

  # This Mac uses Determinate Nix, so nix-darwin must not manage Nix itself.
  # Shared nix.conf and registry values are routed to determinateNix by the
  # base profile.
  nix.enable = false;
  determinateNix.enable = true;
}
