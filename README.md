# nix-config

One flake, four evaluators: NixOS, nix-darwin, standalone Home Manager, and
system-manager. Every machine is a single entry in a shared host registry; the
builders in `lib/` turn that entry into whichever configuration kinds it asks
for.

**System and home are separate closures everywhere.** Home Manager is never a
NixOS or nix-darwin module — not even on machines this repo also owns the OS of.
A host's users become standalone `homeConfigurations`, so `just switch` /
`just darwin` rebuild the machine and nothing else, and a user changing their own
config runs `just home` without a system rebuild or root. The two sides meet only
at `config.my.host` and at `nixos/modules/users.nix`, which creates the accounts.

New here and only responsible for your own account? Read
[`docs/home-quickstart.md`](docs/home-quickstart.md) instead of this file.

## Host registry

`nixos/hosts/default.nix` maps a name to `nixos/hosts/<name>/default.nix`, which
returns **metadata, not a module**:

```nix
{inputs}: {
  system = "x86_64-linux";
  kind = "nixos";                 # nixos | darwin | home
  roles = ["desktop" "gui"];
  ip = "10.0.0.68";               # presence makes it a deploy-rs target
  sshUser = "root";

  profiles = [...];               # from {nixos,darwin,home}/profiles/default.nix
  modules = [./system.nix ./hardware-configuration.nix];
  externalModules = [...];        # third-party modules out of flake inputs

  systemManager = {               # optional, Linux only
    enable = true;
    modules = [...];
    overlays = [...];             # overlays go here, NOT nixpkgs.overlays
  };

  users.hank.home = {
    profiles = [...];
    modules = [...];
  };
}
```

The same metadata reaches every evaluator as `config.my.host`
(`modules/shared/host-options.nix`): `name`, `system`, `roles`, `users`,
`usernames`, `homeOverlays`. Read it instead of re-deriving host facts.

## Outputs

| Attribute | Built by |
| --- | --- |
| `nixosConfigurations.<host>`, `darwinConfigurations.<host>` | `lib/mkConfigurations.nix` |
| `homeConfigurations."hosts/<host>/<user>"`, also `"<user>@<host>"` | `lib/mkHomeConfigurations.nix` |
| `systemConfigs.<host>` (also `.hosts.<host>`, `.<system>.<host>`) | `lib/mkSystemManagerConfigurations.nix` |
| `deploy.nodes.<host>` — `profiles.system` + one `profiles.home-<user>` per account | `lib/mkDeployNodes.nix` — hosts with an `ip` and `kind = "nixos"` |
| `checks` | deploy-rs `deployChecks` |

## Layout

```text
flake.nix
justfile                        # every rebuild/deploy command
lib/                            # builders + nixpkgs-registry.nix pins
modules/shared/host-options.nix # config.my.host schema
nixos/hosts/<name>/             # default.nix (metadata) + system.nix + hardware-configuration.nix
nixos/profiles/                 # base, desktop, server, virtualisation
nixos/modules/                  # system modules: nix*, users, mihomo, vfio, …
darwin/profiles/                # macOS base (pulls in nixos/modules/nix.nix, users, home-manager-cli)
home/profiles/                  # core, base, gui/{linux,darwin}
home/modules/                   # hyprland, nixvim, ghostty, starship, …
home/users/<name>/              # default.nix + dev.nix (dev is per-user, not a shared profile)
secrets/                        # sops-nix: secrets.yaml + hosts/<host>.yaml
```

## Commands

```bash
just switch <host>          # nixos-rebuild        — system only
just darwin <host>          # darwin-rebuild       — system only
just home                   # home-manager for this machine's own account
just hm <host> <user>       # home-manager, resolves hosts/<host>/<user>
just check                  # nix flake check
just up / just upp <input>  # flake update, all inputs or one
just deploy / just deploy-host <host>
just deploy-system <host> / just deploy-home <host> <user>
```

system-manager has no recipe: `sudo system-manager switch --flake .#<host>`.

## Things that will bite you

- **New files are invisible to Nix until `git add`ed.** The flake reads the git
  tree, so an untracked module silently does not exist.
- **Determinate hosts** (`m1elite`, `m1pro`) set `nix.enable = false`, which
  drops nix-darwin's entire nix module — `nix.settings` and `nix.registry`
  evaluate to nothing, with no error. `nixos/modules/nix-settings.nix` and
  `nix-registry.nix` detect this and route the same values to
  `determinateNix.customSettings` / `determinateNix.registry`. Put shared
  nix.conf values there, never on a host directly.
- **`determinateNix.customSettings` is written verbatim** into
  `nix.custom.conf`, so use the `extra-*` forms. A plain `trusted-public-keys`,
  `substituters` or `trusted-users` replaces rather than merges, dropping
  `cache.nixos.org-1`, `cache.flakehub.com` or `root` respectively.
- **system-manager imports only nixpkgs' `config/nix.nix`.** `nix.settings`
  exists there; `nix.registry`, `nixPath`, `channel` and `distributedBuilds` do
  not — hence `nix.nix` (full) vs `nix-settings.nix` (portable). It also cannot
  take `nixpkgs.overlays`: its pkgs comes from `makeSystemConfig`, and defining
  overlays on top recurses through `users-groups.nix`'s `pkgs.shadow`.
- **`mkIf` does not guard option existence.** A definition inside a false `mkIf`
  still counts as a definition, so platform-specific options need
  `lib.optional (options ? foo) (...)` around the whole block.
- **Registry pins live in `lib/nixpkgs-registry.nix`** and are spelled as github
  refs on purpose. The `flake = inputs.nixpkgs` shorthand resolves to
  `type = "path"`, which leaks a machine-local `path:/nix/store/...` entry into
  the flake.lock of any project whose input reads `nixpkgs.url = "nixpkgs"`.
- **A system switch no longer activates any home.** Adding a package to
  `home/` and running `just switch` changes nothing — that used to work and
  quietly does not any more. Run `just home` (or `just hm <host> <user>`).
- **Home modules cannot read `osConfig`.** It only exists when Home Manager is a
  submodule of a system evaluation, which it never is here. Anything a home needs
  to know about its machine goes through `config.my.host`, which every evaluator
  gets from `modules/shared/host-options.nix`.
- **The first standalone activation collides with existing dotfiles.** As a NixOS
  module this was handled by `home-manager.backupFileExtension`; standalone it is
  the `-b backup` flag, which the `just home` / `just hm` recipes pass.

## Deploys

Servers and routers are pushed with deploy-rs over the WireGuard mesh
(`10.0.0.0/24`) from **h610**, the build box — it has `aarch64-linux` binfmt so
it can build the SBC closures locally. `autoRollback` and `magicRollback` are on,
so a deploy that breaks connectivity reverts itself.

Each node carries a `system` profile plus one `home-<user>` profile per account,
activated in that order. Homes are separate closures now, so without those
profiles the accounts on servers — whose owners never log in to run
`home-manager` themselves — would stop being updated. They activate as the target
user via `sudo -H -u <user>`; the `-H` matters, since Home Manager resolves every
path relative to `$HOME` and deploy-rs' default `sudo -u` would leave it pointing
at root's.

Current targets: `b650, h610, n100, r5s, r6s, rpi4, shanghai, tank, x470`.

## CI

`.github/workflows/ci.yml` dry-builds a 15-host matrix on push/PR — Linux hosts
on `ubuntu-latest` (aarch64 via QEMU), `m1elite` and `m1pro` on `macos-latest`.
Pulling the private flake inputs needs the `SSH_PRIVATE_KEY` repo secret (a key
with read access to the private `imdomestic/*` and `HCHogan/*` repos).

## License

MIT
