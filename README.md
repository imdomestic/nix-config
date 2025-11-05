# ❄️ nix-config

Declarative NixOS, nix-darwin, and Home Manager setup with a single flake that scales from servers to laptops—and even standalone HM installs on other distros.

## ✨ Highlights

- 🧩 Flake entry point that keeps **system** and **Home Manager** layers cleanly separated.
- 🖥️ Host registry covering Linux (x86_64/aarch64) and macOS (`aarch64-darwin`, `x86_64-darwin`), plus Home Manager–only machines.
- 👥 Shared profiles + per-user overrides so you can reuse core pieces without shipping unwanted packages.
- 🪟 Role-driven profiles (`desktop`, `server`, `virtualisation`, …) that compose into each host.
- 🏠 HM outputs exposed as `homeConfigurations."hosts/<host>/<user>"`, ideal for non-NixOS distros.
- 🧰 Reusable module library for services (mihomo, vfio, …) and desktop tooling (Hyprland, Kitty, Starship, …).

## 📁 Layout

```text
.
├── flake.nix
├── lib/
│   ├── mkConfigurations.nix      # Builds nixos/darwin systems from host metadata
│   └── mkHomeConfigurations.nix  # Builds per-host Home Manager configs
├── nixos/
│   ├── hosts/<name>/system.nix   # Host-specific NixOS/nix-darwin modules
│   ├── hosts/<name>/hardware-configuration.nix
│   ├── hosts/default.nix         # Host registry
│   ├── modules/                  # System-level reusable modules (nix, users, fcitx5…)
│   └── profiles/                 # Base/desktop/server/virtualisation profiles
├── darwin/
│   └── profiles/                 # macOS-specific base profile(s)
├── home/
│   ├── modules/                  # Home Manager modules (hyprland, kitty, starship…)
│   ├── profiles/                 # Shared HM profiles (core, dev, gui/linux, gui/darwin)
│   └── users/<name>/default.nix  # User-specific adjustments
├── fonts/
└── wallpapers/
```

## 🚀 Usage

Pick the target you want to activate and feed it to the flake.

```bash
# NixOS hosts
sudo nixos-rebuild switch --flake .#tank
# macOS
darwin-rebuild switch --flake .#m3max

# Standalone Home Manager (any distro)
home-manager switch --flake .#"hosts/aarch64-headless/hank"
```

> 🔁 Every host entry lives in `nixos/hosts/<name>/default.nix`. There you pick shared profiles, external modules, and user-specific overrides. Set `kind = "home"` for HM-only targets.

## 📄 License

MIT
