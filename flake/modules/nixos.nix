# NixOS modules that host entries pick by name: `config.flake.modules.nixos.<name>`.
# Only what a host.nix selects needs a name; modules that other modules import
# stay plain relative imports.
{
  flake.modules.nixos = {
    # profiles
    base = ../../system/profiles/base.nix;
    desktop = ../../system/profiles/desktop.nix;
    netdiag = ../../system/profiles/netdiag.nix;
    server = ../../system/profiles/server.nix;
    virtualisation = ../../system/profiles/virtualisation.nix;

    bonsai-conversion = ../../system/modules/bonsai-conversion.nix;
    bonsai-ninfer = ../../system/modules/bonsai-ninfer.nix;
    bonsai-tailnet = ../../system/modules/bonsai-tailnet.nix;
    gaoji-worker = ../../system/modules/gaoji-worker.nix;
    linwhite-smb = ../../system/modules/linwhite-smb/nixos.nix;
    sudo-pwfeedback = ../../system/modules/sudo-pwfeedback.nix;
    vex = ../../system/modules/vex;
  };
}
