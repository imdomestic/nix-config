set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

substituters := "https://mirror.sjtu.edu.cn/nix-channels/store https://cache.nixos.org"

default:
  @just --list

# -------- System rebuild helpers --------
# These touch the system only. Home Manager is standalone on every host, so a
# switch never rebuilds or activates a user's home — use `just home` / `just hm`
# for that.
switch host:
  nixos-rebuild --sudo switch --flake .#"{{host}}"

darwin host:
  darwin-rebuild switch --flake .#"{{host}}"

debug host:
  nixos-rebuild --sudo switch --flake .#"{{host}}" --show-trace --verbose

# -------- Home Manager helpers --------
# `-b backup` is what `home-manager.backupFileExtension` used to do while HM was
# a NixOS module: without it the first standalone activation aborts on any
# pre-existing dotfile it wants to own.

# Activate this machine's own account, resolved as <user>@<host>.
home:
  home-manager switch -b backup --flake .#"$(whoami)@$(hostname -s)"

# Same, without touching anything — see what would change first.
home-dry:
  home-manager switch -b backup --flake .#"$(whoami)@$(hostname -s)" --dry-run

# Activate any host/user pair explicitly.
hm host user:
  home-manager switch -b backup --flake .#"hosts/{{host}}/{{user}}"

hm-dry host user:
  home-manager switch -b backup --flake .#"hosts/{{host}}/{{user}}" --dry-run

# -------- Flake & tooling --------
check:
  nix flake check --option substituters '{{substituters}}'

check-trace:
  nix --show-trace flake check --option substituters '{{substituters}}'

# Verify every sops.secrets key a host declares actually exists in its
# secrets/hosts/<host>.yaml. Without this, a mismatch only surfaces during
# activation — sops-install-secrets fails after services have already been
# restarted. Needs an age key that can decrypt the files.
# usage: just check-sops [host...]   (no args = every host with a sops file)
check-sops *hosts:
  ./scripts/check-sops.sh {{hosts}}

# Cross-check the xray reverse-proxy domains: r5sjp is the bridge side, the
# portals are everyone else, and the reverse-*.hank.internal names have to match
# exactly. A mismatch is silent — both ends start fine, ports listen, Reality
# falls back normally — traffic just dies at the portal.
check-tunnels:
  ./scripts/check-tunnels.sh

# Hand every host's generated xray config to `xray -test`. Neither `nix eval`
# nor check-tunnels catches semantic breakage — an empty realitySettings block
# evaluates fine and renders valid JSON, then xray refuses to start with
# `empty "password"` and the node is down. sops placeholders are replaced with
# structurally valid dummies, so no decryption key is needed.
# usage: just check-xray [host...]
check-xray *hosts:
  ./scripts/check-xray.sh {{hosts}}

# Same idea for sing-box. 1.13 turned several "deprecated but not yet removed"
# spellings into fatal-at-startup errors (legacy DNS servers, missing
# default_domain_resolver) — the config looks fine and the service simply never
# comes up, which on a router means the whole house is offline. The check runs
# on the target host: tun/auto_redirect are Linux-only, so running it on macOS
# fails for platform reasons and yields nothing but false alarms.
# usage: just check-singbox [host...]
check-singbox *hosts:
  ./scripts/check-singbox.sh {{hosts}}

up:
  nix flake update

# Update specific input
# usage: just upp home-manager
upp input:
  nix flake update {{input}}

# -------- deploy-rs (push servers/routers over the wireguard mesh) --------
# 目标是每台设了 `tsIp` 的机器(lib/mkDeployNodes.nix):h610 tank r6s r5s
# rpi4 r2s shanghai r5sjp。走 tailscale 地址,所以从哪台机器发起都行。
#
# **构建发生在目标机上**(节点配置里 remoteBuild = true)。发起方只做求值,
# 不再把整个目标平台的闭包在本地物化一遍 —— 实测那会让发起方下载 641 MiB,
# 而目标机自己已经有其中 88%。ARM 机器原生编也比拿 x86 机器 QEMU 模拟快
# 3.7 倍。
#
# 遇到目标机太弱扛不住的大构建,用 `deploy .#<host> --no-remote-build` 覆盖回
# 发起方构建。
#
# Each node carries a `system` profile plus one `home-<user>` profile per account
# (lib/mkDeployNodes.nix) — the users on servers do not run home-manager
# themselves, so a plain `just deploy` still has to push their homes.

# Build + activate every configured node, system and homes
deploy:
  deploy .

# Deploy a single node, e.g. just deploy-host tank
deploy-host host:
  deploy .#"{{host}}"

# Only the system closure of a node — skips every home-<user> profile
deploy-system host:
  deploy .#"{{host}}".system

# Only one user's home on a node, e.g. just deploy-home tank hank
deploy-home host user:
  deploy .#"{{host}}"."home-{{user}}"

# Deploy everything but skip the flake checks (faster)
deploy-fast:
  deploy . --skip-checks

# Update all inputs, then deploy everything
update-deploy: up deploy

history:
  nix profile history --profile /nix/var/nix/profiles/system

repl:
  nix repl -f flake:nixpkgs

clean:
  # remove all generations older than 7 days
  sudo nix profile wipe-history --profile /nix/var/nix/profiles/system --older-than 7d

gc:
  # garbage collect all unused nix store entries
  sudo nix store gc --debug
  sudo nix-collect-garbage -d

push:
  git add .
  git commit -am "update"
  git push -u origin main
