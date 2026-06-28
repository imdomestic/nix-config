set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

substituters := "https://mirror.sjtu.edu.cn/nix-channels/store https://cache.nixos.org"

default:
  @just --list

# -------- System rebuild helpers --------
switch host:
  nixos-rebuild --sudo switch --flake .#"{{host}}"

darwin host:
  darwin-rebuild switch --flake .#"{{host}}"

debug host:
  nixos-rebuild --sudo switch --flake .#"{{host}}" --show-trace --verbose

# -------- Home Manager helpers --------
hm host user:
  home-manager switch --flake .#"hosts/{{host}}/{{user}}"

hm-dry host user:
  home-manager switch --flake .#"hosts/{{host}}/{{user}}" --dry-run

# -------- Flake & tooling --------
check:
  nix flake check --option substituters '{{substituters}}'

check-trace:
  nix --show-trace flake check --option substituters '{{substituters}}'

up:
  nix flake update

# Update specific input
# usage: just upp home-manager
upp input:
  nix flake update {{input}}

# -------- deploy-rs (push servers/routers over the wireguard mesh) --------
# Run these from the build host (h610). Targets are every host with an `ip`
# in nixos/hosts/<name>/default.nix: shanghai, tank, x470, b650, h610, n100,
# r5s, r6s, rpi4.

# Build + activate every configured node
deploy:
  deploy .

# Deploy a single node, e.g. just deploy-host tank
deploy-host host:
  deploy .#"{{host}}"

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
