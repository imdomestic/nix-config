# system-manager modules that host entries pick by name: `config.flake.modules.systemManager.<name>`.
{
  flake.modules.systemManager = {
    nix-settings = ../../system/modules/nix-settings.nix;
  };
}
