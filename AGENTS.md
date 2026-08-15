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

## System and home are separate closures

Home Manager is **never** a NixOS or nix-darwin module here, not even on hosts
this repo also owns the OS of. Every user is a standalone
`homeConfigurations."hosts/<host>/<user>"` (aliased `"<user>@<host>"`), built by
`lib/mkHomeConfigurations.nix`. `lib/mkConfigurations.nix` builds the system and
adds no home-manager module at all.

- Do not add `inputs.home-manager.{nixos,darwin}Modules.home-manager` to a system
  evaluation, and do not put `home-manager.users.*` in a system module. The whole
  point is that a home change costs no system rebuild and no root.
- **`osConfig` is unavailable** in home modules — it only exists for submodule
  Home Manager. Route host facts through `config.my.host`
  (`modules/shared/host-options.nix`), which all four evaluators share. There is
  currently no `osConfig` reference anywhere in the repo; keep it that way.
- A home change is verified with `just hm-dry <host> <user>`, **not** with
  `just switch` — a system switch does not build homes at all any more. Never
  tell the user a rebuild will pick up an edit under `home/`.
- Conversely, a system-level change does not need a home eval to prove it works,
  and a broken home no longer breaks its host's system eval.
- The two sides meet in exactly three places: `config.my.host`,
  `nixos/modules/users.nix` (which creates the accounts), and
  `nixos/modules/home-manager-cli.nix` (which ships the `home-manager` binary so
  a fresh machine can bootstrap its first activation).
- **Where a package goes.** Default to `home.packages` in the asking user's
  `home/users/<user>/`. `environment.systemPackages` is only for things the
  machine itself needs, or that every account must have regardless of who logs
  in — it costs a system rebuild and root to change.
- On deployable hosts, homes ride along as `deploy.nodes.<host>.profiles.home-<user>`
  (`lib/mkDeployNodes.nix`), because server accounts have no one to run
  `home-manager` interactively.

`docs/home-quickstart.md` is the human-facing version of this for users who only
own their own home. If you change how activation works, update it too.

## Build & verify

Use the `Justfile` recipes:

```sh
just check                # nix flake check (with mirror substituters)
just switch <host>        # nixos-rebuild switch   — system only, no homes
just darwin <host>        # darwin-rebuild switch  — system only, no homes
just home                 # home-manager switch for this machine's account
just hm <host> <user>     # home-manager switch
just hm-dry <host> <user> # home-manager dry run
```

Before claiming a change works, at minimum make sure evaluation passes
(`just check` or an `nix eval`/`--dry-run` of the affected configuration).
Do not run `switch` on the user's behalf unless asked.

### Before any rebuild: freshness check

Before running any `switch`-style command (`just switch` / `just darwin` /
`just hm`, or the underlying `nixos-rebuild` / `darwin-rebuild` /
`home-manager`), always verify the checkout and the running system are
up to date:

1. `git fetch` and check for new remote commits:
   `git log --oneline HEAD..origin/main` (plus `git status` for local drift).
2. Check whether the running generation was built from the current HEAD.
   `configurationRevision` is **not** set in this flake, so compare store
   paths instead: `readlink /run/current-system` vs the evaluated toplevel
   `outPath` of the host's configuration (a `--dry-run` build also shows
   whether anything would change).
3. If the remote has new commits, or the running generation does not match
   the latest code, **stop and report to the user first**: summarize the
   incoming commits (`git log`) and a diff overview (`git diff --stat`), and
   let the user decide whether to pull/rebase before rebuilding. Never
   silently rebuild over an out-of-date checkout.

### After a rebuild: commit and push promptly

The freshness check above is the other half of this rule, and it only works if
everyone's commits actually reach the remote. So once a rebuild/deploy has
landed and the change is committed, **push it**.

**Pushing this repo is pre-authorized — do not stop to ask.** Commit with a real
message and push. (This is a standing instruction from the owner, 2026-08-15.)

Push is not just `git push`: **`git fetch` first and expect the remote to have
moved.** This repo is edited from several machines, so a straight push will
often be rejected. Rebase onto `origin/main`, then — because the incoming
commits are real config changes, not just text — verify every host still
evaluates before pushing:

```sh
for h in <hosts>; do
  nix eval --raw ".#nixosConfigurations.$h.config.system.build.toplevel.drvPath" \
    >/dev/null || echo "★ $h eval failed"
done
```

If the rebase conflicts in a way that is not obviously mechanical, stop and
report — a silently mis-resolved conflict in a host config is worse than an
unpushed commit.

Why it matters, in order of how much it bites:

1. **A machine running code that is not on the remote is unreproducible.** The
   next deploy from a clean checkout silently reverts it, and nobody sees a
   conflict — the change just disappears.
2. The freshness check on every *other* machine will report "up to date" while
   actually being behind, because the commit exists only in one working tree.
3. A dirty tree makes `git status` noise indistinguishable from real drift, so
   the next person skips reading it.

If a change is deployed but deliberately not committed yet (mid-investigation,
say), say so explicitly in the handoff rather than leaving it implicit — a
deployed-but-uncommitted generation is a landmine for the next rebuild.
