{ pkgs, ... }:
{
  system-manager.allowAnyDistro = true;

  environment = {
    systemPackages = with pkgs; [
      neovim
      ripgrep
    ];
  };

  # example services
  systemd.services."nix-store-gc" = {
    description = "Collect unreachable paths from the Nix store";
    startAt = [ "daily" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.nix}/bin/nix-collect-garbage --delete-older-than 30d";
    };
  };

  systemd.services."nix-store-optimise" = {
    description = "Deduplicate store paths to save disk space";
    startAt = [ "weekly" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.nix}/bin/nix-store --optimise";
    };
  };
}

