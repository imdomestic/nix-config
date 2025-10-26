rebuild:
  nixos-rebuild switch --flake . --sudo

darwin:
  darwin-rebuild switch --flake . switch

debug:
  nixos-rebuild switch --flake . --sudo --show-trace --verbose

deploy:
  nixos-rebuild switch --flake .#rpi4 --sudo --target-host nix@rpi4.sanuki.cn --build-host localhost

up:
  nix flake update

# Update specific input
# usage: make upp i=home-manager
upp:
  nix flake update $(i)

history:
  nix profile history --profile /nix/var/nix/profiles/system

repl:
  nix repl -f flake:nixpkgs

clean:
  # remove all generations older than 7 days
  sudo nix profile wipe-history --profile /nix/var/nix/profiles/system  --older-than 7d

gc:
  # garbage collect all unused nix store entries
  sudo nix store gc --debug
  sudo nix-collect-garbage -d

push:
  git add .
  git commit -am "update"
  git push -u origin main
