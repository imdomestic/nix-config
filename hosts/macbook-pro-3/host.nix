{lib, ...}: {
  hosts.macbook-pro-3 = {
    system = "aarch64-darwin";
    kind = "home";
    roles = ["desktop" "gui"];

    users.a123456.modules = [
      {
        # The macOS account name and its actual home directory differ on this
        # machine, so override Home Manager's conventional /Users/<name> path.
        home.homeDirectory = lib.mkForce "/Users/a123456_1_2";
      }
    ];
  };
}
