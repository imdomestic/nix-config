{...}: let
  homeProfiles = import ../../../home/profiles/default.nix;
in {
  system = "x86_64-linux";
  kind = "home";
  roles = ["server"];

  users.z5730136.home = {
    profiles = with homeProfiles; [
      # core only supplies the standalone Home Manager plumbing; base is the
      # sole feature profile on this restricted university account.
      core
      base
    ];
    modules = [
      ../../../home/modules/nixvim
      ({
        lib,
        pkgs,
        ...
      }: {
        home.homeDirectory = lib.mkForce "/mnt/accounts/user/36/z5730136";
        i18n.glibcLocales = lib.mkForce pkgs.glibcLocalesUtf8;
        nix = {
          package = pkgs.nix;
          settings = {
            experimental-features = ["nix-command" "flakes"];
            # The CSE home is NFS-backed; SQLite WAL is unsafe across login nodes.
            use-sqlite-wal = false;
          };
        };
        programs.nixvim = {
          # CSE is SSH-only and uses the OSC 52 clipboard configured by nixvim.
          waylandSupport = lib.mkForce false;
          dependencies.git.package = lib.mkForce pkgs.gitMinimal;
        };
      })
    ];
  };
}
