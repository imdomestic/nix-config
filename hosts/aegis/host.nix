{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.aegis = {
    system = "aarch64-darwin";
    kind = "darwin";
    roles = ["desktop" "gui"];

    modules = [
      ./system.nix
      m.darwin.sudo-pwfeedback
    ];

    externalModules = [
      inputs.determinate.darwinModules.default
    ];

    users.linwhite.modules = [
      m.homeManager.opencode-local-bonsai
      m.homeManager.linwhite-aegis
    ];
  };
}
