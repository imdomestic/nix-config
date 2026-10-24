# nix-darwin modules that host entries pick by name: `config.flake.modules.darwin.<name>`.
{
  flake.modules.darwin = {
    base = ../../system/profiles/darwin.nix;
    sudo-pwfeedback = ../../system/modules/sudo-pwfeedback.nix;
  };
}
