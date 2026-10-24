{inputs, ...}: {
  hosts.aegis = {
    system = "aarch64-darwin";
    kind = "darwin";
    roles = ["desktop" "gui"];

    modules = [
      ../../system/modules/sudo-pwfeedback.nix
    ];

    externalModules = [
      inputs.determinate.darwinModules.default
    ];

    users.linwhite = {};
  };
}
