{config, ...}: {
  hosts.macbook-pro-3 = {
    system = "aarch64-darwin";
    kind = "home";
    roles = ["desktop" "gui"];

    users.a123456.modules = [config.flake.modules.homeManager.a123456-macbook-pro-3];
  };
}
