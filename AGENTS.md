# AGENTS.md

Guidance for AI agents working in this repo, and the operational reference for
it. `README.md` is the human introduction; architecture, everyday tasks,
commands, deploys and the traps all live here.

## Architecture

One flake, four evaluators: NixOS, nix-darwin, standalone Home Manager, and
system-manager. The flake itself is a flake-parts evaluation: `flake.nix` only
lists inputs and hands import-tree three sets of files — everything under
`flake/`, every `hosts/<name>/host.nix`, every `home/users/<account>/user.nix`.
Those are top-level (flake-parts) modules. Everything else is a plain NixOS /
nix-darwin / Home Manager / system-manager module.

Three typed top-level tables (a misspelled field fails evaluation) describe the
fleet, and `flake/builders/` turns them into configurations:

| Table | Entries | Schema |
| --- | --- | --- |
| `hosts.<name>` | `hosts/<name>/host.nix` | `flake/schema/hosts.nix` |
| `users.<account>` | `home/users/<account>/user.nix` | `flake/schema/users.nix` |
| `placements.<service>` | `flake/placements.nix` | `flake/schema/placements.nix` |

Start reading at `flake/schema/hosts.nix`. Why it is shaped this way:
`docs/decisions.md#flake-parts-tables` and `#system-dir`.

### Layout

```text
flake.nix               # inputs, and the import-tree roots
flake/                  # top-level (flake-parts) modules
  schema/               #   the tables: hosts, users, placements, inventory
  builders/             #   systems, homes, system-manager, deploy
  modules/              #   flake.modules registrations, one file per class
  outputs/              #   packages, ciMatrix, nixidy, hosts, mcImageTag
  placements.nix        #   where fleet services run
  secrets.nix           #   who reads which sops file; renders .sops.yaml
  _lib/                 #   plain files import-tree skips: host-facts, host-options,
                        #   roles, tiers, host-modules (the my.host / my.fleet plumbing)
hosts/<name>/           # every machine, whatever its kind: host.nix + system.nix + hardware-configuration.nix
system/profiles/        # base, server, desktop, netdiag, virtualisation (picked by roles); darwin.nix
system/modules/         # NixOS and nix-darwin modules side by side
system/installers/      # the x86_64-rescue image
home/profiles/          # tier bundles core, shell, interactive, dev; gui/{common,linux,darwin}
home/modules/<app>/     # Home Manager modules that accounts share
home/users/<account>/   # user.nix (table entry), default.nix, dev.nix, nixvim/, the account's own modules
lib/                    # data and helpers modules import: nixpkgs-registry pins, wg*, model tables
pkgs/                   # local packages
secrets/                # sops files: secrets.yaml, hosts/<host>.yaml, clients/, gaoji/
scripts/                # check-* scripts behind the just recipes, plus model/bench tooling
docs/                   # incidents.md, decisions.md, topic docs, runbooks/
Justfile                # every rebuild/deploy command
```

Which class a module under `system/` is for is what its
`flake.modules.<class>` registration (`flake/modules/<class>.nix`) or its
importer says, not the directory. A file only one account uses (its theme, its
variant of an app, its nixvim) lives in `home/users/<account>/`, not
`home/modules/`.

### Hosts

```nix
# hosts/example/host.nix
{config, inputs, ...}: let
  m = config.flake.modules;
in {
  hosts.example = {
    system = "x86_64-linux";
    kind = "nixos";                 # nixos | darwin | home
    roles = ["server" "desktop" "gui"]; # the one knob for what the machine is
    tsName = "example.inner.imdomestic.com"; # opts into tailscale, deploy, telemetry
    ip = "10.0.0.68";               # optional WireGuard address
    sshUser = "root";
    inChina = true;                 # SJTU mirror first; off by default
    ageKey = "age1…";               # the host's sops key (ssh host key via ssh-to-age)
    maxTier = "interactive";        # caps every account's home tier here
    buildOn = "r6s";                # too small to build itself (see 小内存机器)
    lanRoutes = ["192.168.22.0/24"]; # LAN advertised to the tailnet; must be unique

    modules = [./system.nix ./hardware-configuration.nix m.nixos.vex];
    hardwareModules = [...];        # nixos-hardware modules
    externalModules = [...];        # third-party modules out of flake inputs

    systemManager = {               # optional, Linux only
      enable = true;
      modules = [m.systemManager.nix-settings ./system-manager.nix];
      overlays = [...];             # overlays go here, NOT nixpkgs.overlays
    };

    users = {
      hank = {};                    # has an account here; its home comes from users.hank
      linwhite = {
        tier = "interactive";       # lower than its default, on this host
        gui.profile = m.homeManager.gui-common; # replaces its GUI layers here
        modules = [./home.nix];     # extra home modules, loaded last
        extraGroups = ["wheel"];    # replaces the default groups
        nixos.uid = 501;            # merged into users.users.linwhite
        ageKey = "age1…";           # this account's sops key on this machine
      };
    };
  };
}
```

`roles` is an enum (`flake/_lib/roles.nix`) and the only thing that picks
system profiles: every host gets `base`, then `server`, `desktop`, `router`
(netdiag) and `vm-host` (virtualisation) add theirs, in that order. `gui` gives
accounts their GUI layers, `monitor` / `monitor-gateway` turn on monitoring.
`server` + `desktop` compose: the server profile leaves graphics, printing,
pipewire and NetworkManager to the desktop one, whose input method is
`my.inputMethod` (fcitx5; the GNOME/ibus hosts set `"ibus"`).

The fact fields (`name`, `system`, `roles`, `inChina`, `tsName`, `lanRoutes`,
`gpuMonitoring`, `clusterControl`, `homeOverlays`) are declared once in
`flake/_lib/host-facts.nix` and reach every evaluator as `config.my.host`,
with `users` and `usernames`. `inChina` (off by default) is the only thing that
puts the SJTU mirror in front of the substituters (and Homebrew's bottles).
Modules that need to see past their own host read
`config.my.fleet`: `hosts` (every entry's facts), `inventory` (the hosts with a
tsName) and `placements` (resolved to a tsName). Never `import` the registry
from a module. Evaluation fails if two hosts advertise the same `lanRoutes`, a
`kind` does not match its `system`, or a `buildOn` names an unusable builder.

Modules a `host.nix` or `user.nix` picks by name are registered as
`flake.modules.<class>.<name>` (classes `nixos`, `darwin`, `homeManager`,
`systemManager`). The values are plain paths, not flake-parts' class-tagged
wrappers (`flake/flake-parts.nix` says why). Modules that only other modules
import stay relative imports.

### Accounts and home tiers

```nix
# home/users/hank/user.nix
{config, ...}: let
  hm = config.flake.modules.homeManager;
in {
  flake.modules.homeManager = {hank = ./default.nix; hank-dev = ./dev.nix; …};
  users.hank = {
    tier = "dev";                   # default on every host
    module = hm.hank;               # loaded on every host
    dev = hm.hank-dev;              # at the dev tier, in place of home/profiles/dev.nix
    gui.linux.modules = [hm.hank-gnome hm.ibus];
    gui.darwin = {profile = hm.gui-darwin; modules = [hm.hank-aerospace];};
    sshKeys = [...];                # may log in as this account, wherever it exists
    ageKeys."1" = "age1…";          # sops keys tied to no registry machine
  };
}
```

The table is keyed by account name; an account called something else on one
machine gets its own entry reusing the module (`users.a123456` in
`home/users/fendada/user.nix`). Tiers are `minimal < shell < interactive < dev`
(`flake/_lib/tiers.nix`): an account's tier on a host is its host-level `tier`
(else its default), capped by the host's `maxTier`. `flake/builders/homes.nix`
composes a home as core → shell → interactive → gui profile → the account's
module → its dev module → its gui modules → the host's extra modules; GUI
layers load only on `gui` hosts, from the shell tier up. An account's
differences go in its own directory or its entry on that host, never in an
`if config.home.username == …` inside a shared module.

### Outputs

| Attribute | Built by |
| --- | --- |
| `nixosConfigurations.<host>`, `darwinConfigurations.<host>` | `flake/builders/systems.nix` |
| `homeConfigurations."hosts/<host>/<user>"`, also `"<user>@<host>"` | `flake/builders/homes.nix` |
| `systemConfigs.<host>` (also `.hosts.<host>`, `.<system>.<host>`) | `flake/builders/system-manager.nix` |
| `deploy.nodes.<host>` — `profiles.system` + one `profiles.home-<user>` per account | `flake/builders/deploy.nix` — NixOS hosts with a `tsName` |
| `deployChecks` | deploy-rs checks, one per node; deliberately not `checks` |
| `ciMatrix` | the CI host list, derived by rule from the registry |
| `packages` | the few local builds pushed to `imdomestic.cachix.org` |
| `sopsConfig` | the rendered `.sops.yaml` (`flake/secrets.nix`) |
| `hosts`, `modules` | the evaluated registry; `flake.modules` |

## Common tasks

Every new file has to be `git add`ed before Nix sees it — an untracked
`host.nix` or `user.nix` is a host or account that silently does not exist.

**Add a machine.**
1. Create `hosts/<name>/` with `host.nix` (`system`, `kind`, `roles`, `users`)
   and, for `nixos` / `darwin`, `system.nix` + `hardware-configuration.nix`.
2. A `tsName` opts it into Tailscale and Tailscale SSH, deployment, telemetry
   and monitoring; the first login to headscale is done once on the machine.
   CI picks it up from `ciMatrix` on its own.
3. Too small to build: `buildOn`. A LAN behind it: `lanRoutes` (headscale's
   policy approves it from the registry).
4. Secrets: `ssh-keyscan -t ed25519 <host> | ssh-to-age` into `ageKey`,
   `just sops-config`, then create `secrets/hosts/<name>.yaml`.
5. First activation on the machine itself (`nixos-rebuild switch --flake
   .#<name>` / `darwin-rebuild`); later ones through deploy-rs or `just switch`.

**Retire a machine.** Delete `hosts/<name>/` and `secrets/hosts/<name>.yaml`,
run `just sops-config`, then `sops updatekeys` on every file it could read
(`sops rotate` to really revoke: old ciphertexts in git history still open
with its key). Remove the node from headscale. If the reason is not obvious,
add a `docs/decisions.md` entry.

**Add or change an account.** An existing account on another machine is
`users.<account> = {};` in that `host.nix`. A new account is
`home/users/<account>/user.nix` (registers its modules, sets `module`, `tier`,
`gui`, `sshKeys`, `ageKeys`) plus its `default.nix`. Per-host exceptions go in
that host's account entry. A key for one account goes in its `sshKeys`;
`system/modules/ssh/keys.nix` is for keys trusted as every account, root
included.

**Change what a machine is.** Edit its `roles`. A new role is an entry in
`flake/_lib/roles.nix`; if it brings profiles, also add it to `profileOrder`
in `flake/builders/systems.nix`.

**Add or move a fleet service.** Its address lives in `flake/placements.nix`
(`host`, `port`); clients read `config.my.fleet.placements.<service>`. Moving it
is that line plus moving the server module to the new host.

**Open a port.** The module that listens declares it — tailnet-only services on
`networking.firewall.interfaces.tailscale0`. Never turn a host's firewall off
(see the firewall trap below).

**Update inputs.** `llm-agents` updates itself (see CI). Anything else:
`just upp <input>`, or `just up` for all — judge the result by
`nix store diff-closures`, not commit count; a new kernel or GPU driver means
deploying with `--boot` and rebooting.

## Rules

### Use native module options, never copy dotfiles

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

### Neovim: nixvim only

Neovim is configured with **nixvim** (flake input, pinned to the `nixos-26.05`
branch). Each account's nixvim lives in its own directory:
`home/users/hank/nixvim/` is Hank's terminal baseline (`default.nix`), with
`vscode.nix` for VS Code and `editing.nix` shared by both.
`home/users/{kenneth,linwhite}/nixvim/` are independent copies (forked from
hank's on 2026-10-06): each has its own `base.nix`, `editing.nix` and
`snippets/`, plus `default.nix` with that account's overrides. A change in one
does not reach the others; only `home/modules/nixvim/options.nix` is shared.

- **Never copy `.lua` files or a whole `nvim/` directory into the repo.**
- Declare plugins via `plugins.*`, options via `opts`/`globals`, keymaps via
  `keymaps` — all in Nix.
- Inline Lua is acceptable only for small glue that nixvim cannot express,
  via `extraConfigLua` or `plugins.<name>.settings.*.__raw`; keep it minimal.

### System and home are separate closures

Home Manager is **never** a NixOS or nix-darwin module here, not even on hosts
this repo also owns the OS of. Every account is a standalone
`homeConfigurations."hosts/<host>/<user>"`, and `flake/builders/systems.nix`
adds no home-manager module at all.

- Do not add `inputs.home-manager.{nixos,darwin}Modules.home-manager` to a system
  evaluation, and do not put `home-manager.users.*` in a system module. The whole
  point is that a home change costs no system rebuild and no root.
- **`osConfig` is unavailable** in home modules — route host facts through
  `config.my.host` / `config.my.fleet`, which all four evaluators share. There is
  no `osConfig` reference anywhere in the repo; keep it that way.
- A home change is verified with `just hm-dry <host> <user>`, **not** with
  `just switch` — a system switch does not build homes at all. Never tell the
  user a rebuild will pick up an edit under `home/`.
- Conversely, a system-level change does not need a home eval to prove it works,
  and a broken home does not break its host's system eval.
- The two sides meet in exactly three places: `config.my.host`,
  `system/modules/users.nix` (which creates the accounts), and
  `system/modules/home-manager-cli.nix` (which ships the `home-manager` binary so
  a fresh machine can bootstrap its first activation).
- **Where a package goes.** Default to `home.packages` in the asking user's
  `home/users/<user>/`; if every account at some tier should have it, the tier
  bundle in `home/profiles/`. `environment.systemPackages` is only for things the
  machine itself needs, or that every account must have regardless of who logs
  in — it costs a system rebuild and root to change.

### Where prose goes: `docs/`, not a 40-line comment block

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
`docs/incidents.md#<anchor>`. Their dated entries keep the paths of their day.

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

## Build, verify, push

```sh
just check                # nix flake check (with mirror substituters)
just switch <host>        # nixos-rebuild switch   — system only, no homes
just darwin <host>        # darwin-rebuild switch  — system only, no homes
just home / home-dry      # home-manager switch for this machine's own account
just hm <host> <user>     # home-manager switch, resolves hosts/<host>/<user>
just hm-dry <host> <user> # home-manager dry run
just up / just upp <input>            # flake update, all inputs or one
just deploy / just deploy-host <host> # deploy-rs, see "Deploys"
just deploy-system <host> / just deploy-home <host> <user>
just deploy-built <host>  # a `buildOn` host's system, via its builder
just sops-config          # regenerate .sops.yaml from flake/secrets.nix
just check-sops / check-xray / check-singbox [host...]; just check-tunnels
```

system-manager has no recipe: `sudo system-manager switch --flake .#<host>`.
`just push` commits everything as "update" — don't use it; write a real
commit message. Do not run `switch` on the user's behalf unless asked.

Before claiming a change works, at minimum make sure evaluation passes
(`just check`, or an `nix eval` / `--dry-run` of the affected configuration).
A change meant to be behaviour-neutral (a move, a refactor) is proven by
comparing the drvPath of every output against the previous commit
(`nix eval --raw "git+file://$PWD?rev=<old>#<attr>.drvPath"` vs the working
tree). tank's toplevel and `nixidyEnvs.x86_64-linux` do import-from-derivation,
so on a Mac they need an x86_64-linux machine to build that part.

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

### After a change: commit and push promptly

The freshness check above only works if everyone's commits actually reach the
remote. So once a change is committed — and certainly once it is deployed —
**push it**.

**Pushing this repo is pre-authorized — do not stop to ask.** Commit with a real
message and push. (This is a standing instruction from the owner, 2026-08-15.)
Commit only the files you changed: other sessions work in the same checkout.

Push is not just `git push`: **`git fetch` first and expect the remote to have
moved** — other machines push, and so does the llm-agents bot every hour.
Rebase onto `origin/main`, then, because incoming commits are real config
changes, verify every host still evaluates before pushing:

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

### 小内存机器不在自己身上编译

有几台机器**不要在目标机上跑 `nixos-rebuild build`**。一次全量 input 更新足以把
它们从网络上打下来，而机器在国内、人不一定在，掉线就等于砖。每台指定一个同架构
的构建机，目标机只收闭包、跑 `switch-to-configuration`，几乎没有负载。

| 目标 | 内存 | 构建机 | 构建机地址 |
|---|---|---|---|
| `r2s` `r5s` `gizmo` `rpi4` | 1–4 GB | `r6s`（8 核 / 7.6 GB / aarch64） | `hank@r6s` |
| `tokyo` | 2 GB | `tank`（20 核 / 64 GB / x86_64） | `hank@tank` |

对应关系以 registry 的 `buildOn` 为准（表里是它的抄本加上内存数字），求值时会
校验构建机存在、同架构、有 tsName。`just deploy` 只推这几台的 home，
`just deploy-host` / `deploy-system` 拒绝它们；系统用 `just deploy-built <host>`，
它就是下面这条命令，外加先确认构建机的 checkout 快进到和本地完全相同的 HEAD：

```sh
ssh hank@<构建机> \
  'nixos-rebuild boot --flake ~/.config/nix-config#<host> --target-host root@<tsName>'
```

以 `hank` 身份跑，不是 root：仓库在 `/home/hank/.config/nix-config`，root 打不开
（libgit2 报 not owned by current user），而 `--target-host root@` 已经解决了目标
机那边的权限。构建机到目标机的 root ssh 要先通。`boot` 没有 magicRollback，
改防火墙、网络这类会断连的东西时先用 `test`，出了问题重启就回到原来的代。

踩过一次，见 `docs/incidents.md#arm-boxes-oom-on-local-build`。
用户在当前任务中明确指定构建机时按该指令执行，先核对资源并限制构建并发；
2026-09-15 的 h310、taipan、rpi4 本机构建例外与实测见
`docs/max-ssh-operations.md#2026-09-15-fleet-rollout`。

## Deploys

Servers and routers are deployed with deploy-rs using the MagicDNS names in
`tsName`. The initiator must resolve `*.inner.imdomestic.com`; see
`docs/tailscale-names.md`. `autoRollback` and `magicRollback` are enabled.
Targets are every NixOS host with a `tsName`; list them from the flake instead
of trusting a hand-written list:

```sh
nix eval --json .#deploy.nodes --apply builtins.attrNames
```

- **Builds happen on the initiator.** Nodes do not set `remoteBuild`, so
  deploying a Linux host from a Mac needs `--remote-build` (build on the
  target); `docs/incidents.md#deploy-remote-build` has the history. Never for
  the small boxes — they go through their builders (above).
- **Pass `--skip-checks`.** Without it deploy-rs first runs the flake's checks,
  which takes long and a lot of memory; CI's matrix already checks each node.
- **A new kernel or GPU driver: `--boot`, then reboot.** `switch` would leave the
  new userspace driver talking to the old loaded kernel module, and GPU services
  restarted by the switch fail until the reboot. Look at
  `nix store diff-closures` of the built system first.
- Each node carries a `system` profile plus one `home-<user>` profile per
  account, activated in that order, so server accounts — whose owners never run
  `home-manager` themselves — keep being updated. They activate as the target
  user via `sudo -H -u <user>` (the `-H` keeps `$HOME` right) with
  `HOME_MANAGER_BACKUP_EXT=backup`, so a file a home takes over for the first
  time is moved to `<name>.backup` instead of failing the activation.

Max operates these targets through ordinary SSH as the full-sudo `max` account,
using its own Tailscale client. The bot runs on `tank` as `max-service`.
Configuration and dated rollout evidence: `docs/max-ssh-operations.md`.

## CI

- `.github/workflows/ci.yml` runs `nix flake check`, then dry-builds one job per
  host from the flake's `ciMatrix` output: every registry host with a system
  configuration (`kind != "home"`), except `x86_64-darwin`, which has no runner.
  x86_64-linux runs on `ubuntu-latest`, aarch64-linux on native
  `ubuntu-24.04-arm`, darwin on `macos-latest`. A new host joins CI on its own;
  never hand-copy a host list into the workflow. It also fails if `.sops.yaml`
  drifts from `flake/secrets.nix`.
- `.github/workflows/cachix.yml` builds the flake's `packages` output and pushes
  it to `imdomestic.cachix.org`.
- `.github/workflows/update-llm-agents.yml` bumps the `llm-agents` input every
  hour, builds the packages homes use from it on x86_64-linux and
  aarch64-darwin, evaluates a few dev homes, and commits straight to main as
  `github-actions[bot]`. Pushes made with `GITHUB_TOKEN` do not trigger ci.yml.
- Pulling the private flake inputs needs the `SSH_PRIVATE_KEY` repo secret (a key
  with read access to the private `imdomestic/*` and `HCHogan/*` repos). macOS
  runners need the Determinate installer: the classic one aborts on their
  pre-existing `_nixbld` users.

## Things that will bite you

- **import-tree loads every `.nix` under `flake/`** as a flake-parts module.
  Plain helpers go under `flake/_lib/` (import-tree skips any path containing
  `/_`). Under `hosts/` and `home/users/` only `host.nix` / `user.nix` load.
- **Two `config`s.** In `flake/`, `host.nix` and `user.nix`, `config` is the
  flake-level one (`config.hosts`, `config.flake.modules`); inside a module
  value it is that evaluation's.
- **Don't wrap modules you put in a host's lists.** The module system orders
  definitions by import depth, so an extra `imports` layer reorders
  `environment.systemPackages` / `home.packages` — and buildEnv's
  `ignoreCollisions` lets order decide which package wins a colliding file. This
  is why `flake.modules` holds plain paths.
- **An attribute defined twice in one attrset** (`networking = { firewall = …; }`
  plus `networking.firewall.x = …`) merges on a current Nix but is an error on
  older ones (`docs/incidents.md#nix-dup-attr-ci`, from when CI ran 2.22).
  Nothing here runs those any more; keep each path in one place anyway.
- **`.sops.yaml` is generated.** Who reads which secret is decided in
  `flake/secrets.nix`; keys live in the registry (`hosts.<name>.ageKey`,
  `hosts.<name>.users.<account>.ageKey`, `users.<account>.ageKeys`). After
  changing either, run `just sops-config`, then `sops updatekeys` on each file
  whose readers changed.
- **Every NixOS host runs the firewall** (nftables backend), except marble,
  whose network namespace is Android's (`docs/decisions.md#marble-no-firewall`).
  `openFirewall` is left to each module. Routers trust `br-lan` (dae / mihomo
  hand LAN connections to arbitrary ports to INPUT); hosts whose LAN NIC carries
  a public IPv6 (tank, x470, gizmo) trust only container and VM bridges and
  allow ports per interface. `checkReversePath = false` wherever policy routing
  or transparent proxying runs. Forwarding is not filtered, so a router's
  firewall does not shield the LAN behind it.
- **sshd takes keys only** (`system/modules/ssh/policy.nix`, in the base
  profile; macOS gets the same as an sshd_config.d drop-in). On tailnet
  addresses port 22 is Tailscale SSH and never reaches sshd.
- **Determinate hosts** (`praxic`, `aegis`, `alex`) set `nix.enable = false`,
  which drops nix-darwin's entire nix module — `nix.settings` and `nix.registry`
  evaluate to nothing, with no error. `system/modules/nix-settings.nix` and
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
- **The first standalone activation collides with existing dotfiles.** `just
  home` / `just hm` pass `-b backup`; deploy-rs profiles set the same backup
  extension.
- **An attribute set given as `postInstall = ""` still changes the derivation.**
  Platform-only build steps go in `lib.optionalAttrs` so the other platforms'
  drvPaths stay put (`pkgs/pi-math`, `pkgs/opencode-latex`).
