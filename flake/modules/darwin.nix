# nix-darwin modules that host entries pick by name: `config.flake.modules.darwin.<name>`.
{
  flake.modules.darwin = {
    base = ../../darwin/profiles/base.nix;
    sudo-pwfeedback = ../../nixos/modules/sudo-pwfeedback.nix;
  };
}
