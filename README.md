# nix-config

One flake, four evaluators: NixOS, nix-darwin, standalone Home Manager, and
system-manager. Every machine is a single entry in a shared host registry, and
every user's home is its own closure, separate from the system it runs on.

## How I Work

This repository is my machines, not a template. It isn't meant to be a turnkey
way to copy my setup or to learn Nix, and a lot of it only makes sense if you
live on my network. I'm not a Nix expert either. I value the fleet staying up
over the config being pretty, so when something here looks strange, there is
usually a dated entry in `docs/` about the afternoon that made it that way.

My main machine is a Mac (`m1elite`). Day to day I live in three apps: Arc for
browsing, Raycast for launching everything, and Ghostty for the terminal. The
actual work happens inside Ghostty with tmux + Neovim (nixvim), either locally
or over SSH on whichever box has the hardware the job needs.

Behind that is a small fleet, spread over a few places on purpose:

* `tank` is the home server: storage, PostgreSQL, Matrix, Prometheus/Grafana,
  and the bots.
* `b650` has the GPU and serves local models.
* `h610` runs the second copy of monitoring. It lives in a different failure
  domain from `tank` deliberately; when `tank`'s side lost power for a whole
  day, `h610` stayed up the entire time.
* `shanghai` is a 2 GB box that fronts Grafana and runs a DERP relay.
* `r2s`, `r5s`, `r6s` and `rpi4` are small ARM boxes that keep the network
  running.

Inevitably I get asked **why isn't Home Manager a NixOS module?** Because
other people log into my machines. They should be able to change their own
shell without root and without rebuilding my system, and a broken home
shouldn't be able to break the host it lives on. It costs two commands
instead of one. Worth it.

I edit this repo from whichever machine I'm sitting at, so `origin/main` moves
under me constantly. The rule is: fetch, rebase, eval every host, push. A
machine running a commit that isn't on the remote gets quietly reverted by the
next deploy from a clean checkout, and nobody notices until something's
missing.

A fair share of the commits here are written by coding agents (Claude Code,
Codex) working in this checkout. [`AGENTS.md`](AGENTS.md) is the rulebook I
hand them, and some of its rules point straight at the incident that
produced them. Separately, Max, an LLM bot, sits in a couple of group chats and
does ops on the fleet over plain SSH as the `max` account; see
[Max SSH operations](docs/max-ssh-operations.md).

### Common Questions Related To This Workflow

**Where are your dotfiles?** Mostly, there aren't any. Programs are
configured through their module options (`programs.tmux.*`, nixvim instead of
a tree of `.lua` files). When a module can't express something, only that
fragment goes through its escape hatch, e.g. `home/users/hank/init-extra.zsh`
spliced into zsh's init. The other raw files aren't config at all, like the
Claude Code statusline script.

**Do you build on the small boxes?** No. Once was enough: a full input update
built locally knocked three ARM boxes off the network
([`docs/incidents.md#arm-boxes-oom-on-local-build`](docs/incidents.md#arm-boxes-oom-on-local-build)).
Now `r6s` builds for the ARM boxes and `tank` builds for `shanghai`. The target
only receives a closure and runs `switch-to-configuration`.

**How do you deploy?** deploy-rs over Tailscale, addressed by the MagicDNS
names in `tsName`. Each node gets its system profile plus one home profile per
account, because nobody is going to log into a router to run `home-manager`.
`autoRollback` and `magicRollback` are on, which matters a lot when the box
you're deploying is the one routing your packets.

**Your fleet is a hundred commits behind. Isn't that scary?** Not really.
That's the normal state of affairs. I judge a rebuild by its closure
(`nix store diff-closures`), not by the commit count.

**Does this work from China?** Yes. Hosts default to the SJTU mirror
(`my.host.useChinaMirror`); my Mac opts out.

**Twenty-six hosts in one flake? Doesn't one change break everything?**
Sometimes it breaks something. CI dry-builds nearly every host that has a
system config on every push, and since homes are separate closures, a broken home no
longer takes its host's system eval down with it. It works for me.

**Can I use this?** Read the source first. Hosts here have hard-coded IPs,
uids, Tailscale names and secrets you can't decrypt. Steal modules, not hosts.

## Where Things Are

If you want the actual mechanics (the host registry, the outputs, the
commands, how deploys and CI work, and the traps), read
[`AGENTS.md`](AGENTS.md). It's written for the coding agents, but it's the
real reference and it works fine for humans too.

[`docs/incidents.md`](docs/incidents.md) is what went wrong and what misled me
first. [`docs/decisions.md`](docs/decisions.md) is why something isn't there.

## License

MIT
