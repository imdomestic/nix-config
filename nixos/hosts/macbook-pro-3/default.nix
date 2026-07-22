{inputs}: let
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-darwin";
  kind = "home";
  roles = ["desktop" "gui"];

  users.a123456.home = {
    profiles = with homeProfiles; [
      core
    ];
    modules = [
      userModules.fendada.module
      {
        # The macOS account name and its actual home directory differ on this
        # machine, so override Home Manager's conventional /Users/<name> path.
        home.homeDirectory = inputs.nixpkgs.lib.mkForce "/Users/a123456_1_2";
      }
    ];
  };
}
