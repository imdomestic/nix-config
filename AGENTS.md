# AGENTS.md

Guidance for AI agents working in this repo. Read `README.md` first for the
architecture (host registry in `nixos/hosts/`, builders in `lib/`, host
metadata exposed as `config.my.host`).

## Core rule: use native module options, never copy dotfiles

**Always configure programs through the native NixOS / nix-darwin /
Home Manager module options** (`programs.*`, `services.*`, etc.).
**Do not** vendor an app's original config file into the repo and ship it with
`home.file`, `xdg.configFile`, `environment.etc`, or `builtins.readFile`.

- Wrong: copying a `starship.toml` / `.tmux.conf` / `kitty.conf` into the repo
  and symlinking it into place.
- Right: `programs.starship.settings`, `programs.tmux.*`, `programs.kitty.*` —
  express the same settings as Nix attributes.
- If a module lacks an option for a specific setting, use its escape hatch
  (`extraConfig`, `settings`, `extraOptions`) for **only that fragment**, and
  keep everything else in typed options.
- Only fall back to raw files for assets that are genuinely not configuration
  (scripts, wallpapers, snippets), e.g. `home/modules/claude-code/statusline.sh`.

## Neovim: nixvim only

Neovim is configured with **nixvim** (flake input, pinned to the
`nixos-26.05` branch). The module lives in `home/modules/nixvim/`.

- **Never copy `.lua` files or a whole `nvim/` directory into the repo.**
- Declare plugins via `plugins.*`, options via `opts`/`globals`, keymaps via
  `keymaps` — all in Nix.
- Inline Lua is acceptable only for small glue that nixvim cannot express,
  via `extraConfigLua` or `plugins.<name>.settings.*.__raw`; keep it minimal.
- Per-user variations follow the existing pattern (see
  `home/modules/nixvim/options.nix` and `linwhite.nix`).

## Layout conventions

- `home/modules/<app>/` — one directory per app, Home Manager modules.
- `home/profiles/` — bundles of modules (`base`, `core`, `dev`, `gui`).
- `nixos/{hosts,modules,profiles}/`, `darwin/profiles/`, `modules/shared/` —
  system-level equivalents.
- New machines are added as metadata in `nixos/hosts/<name>/default.nix` and
  registered in `nixos/hosts/default.nix`. Read host facts from
  `config.my.host` instead of re-deriving them.
- Overlays for system-manager hosts go in `systemManager.overlays`, not
  `nixpkgs.overlays` (see README).

## Build & verify

Use the `Justfile` recipes:

```sh
just check                # nix flake check (with mirror substituters)
just switch <host>        # nixos-rebuild switch
just darwin <host>        # darwin-rebuild switch
just hm <host> <user>     # home-manager switch
just hm-dry <host> <user> # home-manager dry run
```

Before claiming a change works, at minimum make sure evaluation passes
(`just check` or an `nix eval`/`--dry-run` of the affected configuration).
Do not run `switch` on the user's behalf unless asked.
