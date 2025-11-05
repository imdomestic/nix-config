set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

substituters := "https://mirrors.ustc.edu.cn/nix-channels/store https://cache.nixos.org"

default:
  @just --list

# -------- System rebuild helpers --------
switch host:
  sudo nixos-rebuild switch --flake .#"{{host}}"

darwin host:
  darwin-rebuild switch --flake .#"{{host}}"

debug host:
  sudo nixos-rebuild switch --flake .#"{{host}}" --show-trace --verbose

deploy host='rpi4' target='nix@rpi4.sanuki.cn':
  sudo nixos-rebuild switch --flake .#"{{host}}" --target-host {{target}} --build-host localhost

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
