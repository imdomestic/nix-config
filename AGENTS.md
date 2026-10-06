# AGENTS.md

Guidance for AI agents working in this repo, and the operational reference for
it. `README.md` is the human introduction; architecture, commands, deploys and
the traps all live here.

## Architecture

One flake, four evaluators: NixOS, nix-darwin, standalone Home Manager, and
system-manager. Every machine is a single entry in a shared host registry; the
builders in `lib/` turn that entry into whichever configuration kinds it asks
for.

### Host registry

`nixos/hosts/default.nix` maps a name to `nixos/hosts/<name>/default.nix`, which
returns **metadata, not a module**:

```nix
{inputs}: {
  system = "x86_64-linux";
  kind = "nixos";                 # nixos | darwin | home
  roles = ["desktop" "gui"];
  tsName = "example.inner.imdomestic.com"; # deployment and telemetry opt-in
  ip = "10.0.0.68";               # optional separate WireGuard address
  sshUser = "root";

  profiles = [...];               # from {nixos,darwin,home}/profiles/default.nix
  modules = [./system.nix ./hardware-configuration.nix];
  hardwareModules = [...];        # nixos-hardware modules
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

`lib/my-host.nix` forwards the metadata to every evaluator as `config.my.host`
(schema in `modules/shared/host-options.nix`): `name`, `system`, `roles`,
`tsName`, `lanRoutes`, `gpuMonitoring`, `clusterControl`, `users`, `usernames`,
`homeOverlays`, plus `useChinaMirror` (defaults on; hosts opt out in
`system.nix`). Read it instead of re-deriving host facts.

### Outputs

| Attribute | Built by |
| --- | --- |
| `nixosConfigurations.<host>`, `darwinConfigurations.<host>` | `lib/mkConfigurations.nix` |
| `homeConfigurations."hosts/<host>/<user>"`, also `"<user>@<host>"` | `lib/mkHomeConfigurations.nix` |
| `systemConfigs.<host>` (also `.hosts.<host>`, `.<system>.<host>`) | `lib/mkSystemManagerConfigurations.nix` |
| `deploy.nodes.<host>` — `profiles.system` + one `profiles.home-<user>` per account | `lib/mkDeployNodes.nix` — hosts with a `tsName` and a `nixosConfigurations` entry |
| `deployChecks` | deploy-rs checks, one per node; deliberately not `checks` (see `flake.nix`) |
| `ciMatrix` | the CI host list, derived by rule from the registry |
| `packages` | the few local builds pushed to `imdomestic.cachix.org` |
| `hosts` | the raw registry |

### Layout

```text
flake.nix
Justfile                        # every rebuild/deploy command
lib/                            # builders, my-host.nix, nixpkgs-registry.nix pins
modules/shared/host-options.nix # config.my.host schema
nixos/hosts/<name>/             # default.nix (metadata) + system.nix + hardware-configuration.nix
nixos/profiles/                 # base, desktop, server, netdiag, virtualisation
nixos/modules/                  # system modules: nix*, users, mihomo, monitoring, vfio, …
darwin/profiles/                # macOS base (pulls in nixos/modules/nix.nix, users, home-manager-cli)
home/profiles/                  # core, base, interactive, gui/{linux,darwin}; dev.nix is imported per user
home/modules/                   # one directory per app: nixvim, ghostty, tmux, vicinae, …
home/users/<name>/              # default.nix (+ dev.nix where the user has one)
pkgs/                           # local packages (tmux-agent-sidebar, …)
scripts/                        # check-* scripts behind the just recipes, plus model/bench tooling
secrets/                        # sops-nix: secrets.yaml + hosts/<host>.yaml
docs/                           # incidents.md, decisions.md, topic docs, runbooks/
```

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
`nixos-26.05` branch). The module lives in `home/modules/nixvim/`. There is no
`default.nix` at that root — Hank's terminal baseline is `hank/default.nix`,
with `hank/vscode.nix` for VS Code and `hank/editing.nix` shared by both.
`kenneth/` and `linwhite/` are independent copies (forked from hank's on
2026-10-06): each has its own `base.nix`, `editing.nix` and `snippets/`, plus
`default.nix` with that user's overrides. A change under `hank/` does not reach
them, and theirs do not reach hank; only `options.nix` is shared. Import these
entry files explicitly.

- **Never copy `.lua` files or a whole `nvim/` directory into the repo.**
- Declare plugins via `plugins.*`, options via `opts`/`globals`, keymaps via
  `keymaps` — all in Nix.
- Inline Lua is acceptable only for small glue that nixvim cannot express,
  via `extraConfigLua` or `plugins.<name>.settings.*.__raw`; keep it minimal.
- Per-user variations go in that user's own directory (see
  `home/modules/nixvim/options.nix` and `linwhite/default.nix`).

## Layout conventions

- `home/modules/<app>/` — one directory per app, Home Manager modules.
- `home/profiles/` — bundles of modules (`core`, `base`, `interactive`, `gui`).
  `dev.nix` is not a registry profile: each user's `home/users/<user>/dev.nix`
  imports it.
- `nixos/{hosts,modules,profiles}/`, `darwin/profiles/`, `modules/shared/` —
  system-level equivalents.
- New machines are added as metadata in `nixos/hosts/<name>/default.nix` and
  registered in `nixos/hosts/default.nix`. Read host facts from
  `config.my.host` instead of re-deriving them.
- Overlays for system-manager hosts go in `systemManager.overlays`, not
  `nixpkgs.overlays` (see "Things that will bite you" below).

## Where prose goes: `docs/`, not a 40-line comment block

Comments in `.nix` files answer **「这一行为什么这么写」** and nothing else.
Investigation narratives, benchmark tables, and the paths you tried and
abandoned go in `docs/`, with a **one-line pointer** left at the code site.

| Kind of writing | Where | Test |
|---|---|---|
| 「这一行为什么这么写」 | inline comment | the question occurs to someone staring at that line |
| 「那次到底怎么回事」 — root cause, measured numbers, dead ends | `docs/incidents.md` | it is a story with a date |
| 「某样东西为什么不在」 — a deleted service, a deliberately unset option | `docs/decisions.md` | there is no line to attach it to |

Both docs are reverse-chronological, each entry carries an anchor
(`## 2026-08-16 · 标题 {#anchor}`), and code references them as
`docs/incidents.md#<anchor>`.

**Rule of thumb: a comment block past ~10 lines is the signal.** Not a hard
limit — a dense table of keybindings or a module header explaining why the
module exists can be long and still belong in the file. But if those lines
contain a timeline, a measurement, or a "踩过一次", split it: the conclusion
stays, the story moves.

Why it matters: the story is the part that goes stale. A 40-line block about
one afternoon's debugging buries the one sentence a reader actually needed,
and nobody edits it when the situation changes — so it quietly becomes wrong
while still looking authoritative. In `docs/` it is dated, so a reader knows
what it is. **When you write the incident entry, also write down what
misled you** — the wrong first guess is usually more valuable than the fix.

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

## Build & verify

Use the `Justfile` recipes:

```sh
just check                # nix flake check (with mirror substituters)
just switch <host>        # nixos-rebuild switch   — system only, no homes
just darwin <host>        # darwin-rebuild switch  — system only, no homes
just home / home-dry      # home-manager switch for this machine's own account
just hm <host> <user>     # home-manager switch, resolves hosts/<host>/<user>
just hm-dry <host> <user> # home-manager dry run
just up / just upp <input>            # flake update, all inputs or one
just deploy / just deploy-host <host> # deploy-rs, see "Deploys" below
just deploy-system <host> / just deploy-home <host> <user>
just check-sops / check-xray / check-singbox [host...]; just check-tunnels
```

system-manager has no recipe: `sudo system-manager switch --flake .#<host>`.
`just push` commits everything as "update" — don't use it; write a real
commit message.

Before claiming a change works, at minimum make sure evaluation passes
(`just check` or an `nix eval`/`--dry-run` of the affected configuration).
Do not run `switch` on the user's behalf unless asked.

### 小内存机器不在自己身上编译

有几台机器**不要在目标机上跑 `nixos-rebuild build`**。一次全量 input 更新足以把
它们从网络上打下来，而机器在国内、人不一定在，掉线就等于砖。每台指定一个同架构
的构建机，目标机只收闭包、跑 `switch-to-configuration`，几乎没有负载。

| 目标 | 内存 | 构建机 | 构建机地址 |
|---|---|---|---|
| `r2s` `r5s` `gizmo` `rpi4` | 1–4 GB | `r6s`（8 核 / 7.6 GB / aarch64） | `hank@r6s` |
| `tokyo` | 2 GB | `tank`（20 核 / 64 GB / x86_64） | `hank@tank` |

```sh
ssh hank@<构建机> \
  'nixos-rebuild boot --flake ~/.config/nix-config#<host> --target-host root@<tsName>'
```

以 `hank` 身份跑，不是 root：仓库在 `/home/hank/.config/nix-config`，root 打不开
（libgit2 报 not owned by current user），而 `--target-host root@` 已经解决了目标
机那边的权限。构建机到目标机的 root ssh 要先通。

踩过一次，见 `docs/incidents.md#arm-boxes-oom-on-local-build`。
用户在当前任务中明确指定构建机时按该指令执行，先核对资源并限制构建并发；
2026-09-15 的 h310、taipan、rpi4 本机构建例外与实测见
`docs/max-ssh-operations.md#2026-09-15-fleet-rollout`。

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
3. If the remote has new commits, **rebase onto `origin/main` automatically**,
   preserving unrelated local changes. Summarize the incoming commits and
   diff, verify the rebased configuration, then commit and push the requested
   work without asking whether to synchronize first. This is the owner's
   standing instruction as of 2026-09-06. If the running generation differs,
   report that drift and continue the already-authorized deployment from the
   updated checkout; do not rebuild stale code. Rebase itself does not grant
   permission for a deployment that the user has not requested.

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

## Deploys

Servers and routers are deployed with deploy-rs using the MagicDNS names in
`tsName`. The initiator must resolve `*.inner.imdomestic.com`; see
`docs/tailscale-names.md`. `autoRollback` and `magicRollback` are enabled.

Targets are every host with a `tsName` and a NixOS configuration. List them
from the flake instead of trusting a hand-written list:

```sh
nix eval --json .#deploy.nodes --apply builtins.attrNames
```

**Builds happen on the initiator.** Nodes do not set `remoteBuild` (commit
`0645dfa` commented it out, and deploy-rs defaults to false), so deploying a
Linux host from a Mac needs `--remote-build`; without it deploy-rs tries to
build x86_64-linux locally and fails. The measurements that once argued for
target-side builds, and this contradiction, are in
`docs/incidents.md#deploy-remote-build`. `--remote-build` means building on the
target, so it is **not** an option for the small boxes — they go through their
designated builders (table above).

Each node carries a `system` profile plus one `home-<user>` profile per account,
activated in that order. Homes are separate closures, so without those profiles
the accounts on servers — whose owners never log in to run `home-manager`
themselves — would stop being updated. They activate as the target user via
`sudo -H -u <user>`; the `-H` matters, since Home Manager resolves every path
relative to `$HOME` and deploy-rs' default `sudo -u` would leave it pointing at
root's.

Max operates these targets through ordinary SSH as the full-sudo `max` account,
using its own Tailscale client. The bot runs on `tank` as `max-service`.
Configuration and dated rollout evidence: `docs/max-ssh-operations.md`.

## CI

`.github/workflows/ci.yml` runs `nix flake check`, then dry-builds one job per
host from the flake's `ciMatrix` output: every registry host with a system
configuration (`kind != "home"`), except `x86_64-darwin`, which has no runner.
x86_64-linux runs on `ubuntu-latest`, aarch64-linux on native
`ubuntu-24.04-arm`, darwin on `macos-latest`. A new host joins CI
automatically; never hand-copy a host list into the workflow.

Pulling the private flake inputs needs the `SSH_PRIVATE_KEY` repo secret (a key
with read access to the private `imdomestic/*` and `HCHogan/*` repos).
`.github/workflows/cachix.yml` builds the flake's `packages` output and pushes
it to `imdomestic.cachix.org`.

## Things that will bite you

- **New files are invisible to Nix until `git add`ed.** The flake reads the git
  tree, so an untracked module silently does not exist.
- **Determinate hosts** (`praxic`, `aegis`, `alex`) set `nix.enable = false`,
  which drops nix-darwin's entire nix module — `nix.settings` and `nix.registry`
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
- **A system switch does not activate any home.** Adding a package to `home/`
  and running `just switch` changes nothing. Run `just home` (or
  `just hm <host> <user>`).
- **The first standalone activation collides with existing dotfiles.** That is
  what the `-b backup` flag is for; the `just home` / `just hm` recipes pass it.
