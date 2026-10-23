# NixOS modules that host entries pick by name: `config.flake.modules.nixos.<name>`.
# Only what a host.nix selects needs a name; modules that other modules import
# stay plain relative imports.
{
  flake.modules.nixos = {
    # profiles
    base = ../../nixos/profiles/base.nix;
    desktop = ../../nixos/profiles/desktop.nix;
    netdiag = ../../nixos/profiles/netdiag.nix;
    server = ../../nixos/profiles/server.nix;
    virtualisation = ../../nixos/profiles/virtualisation.nix;

    bonsai-conversion = ../../nixos/modules/bonsai-conversion.nix;
    bonsai-ninfer = ../../nixos/modules/bonsai-ninfer.nix;
    bonsai-tailnet = ../../nixos/modules/bonsai-tailnet.nix;
    gaoji-worker = ../../nixos/modules/gaoji-worker.nix;
    linwhite-smb = ../../nixos/modules/linwhite-smb.nix;
    sudo-pwfeedback = ../../nixos/modules/sudo-pwfeedback.nix;
    vex = ../../nixos/modules/vex;
  };
}
