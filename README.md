# ❄️ nix-config

Declarative NixOS, nix-darwin, and Home Manager configuration designed for multi-host and multi-user workflows.

## ✨ Highlights

- 🧩 Flake-based entry point with a clean separation between **system** and **Home Manager** layers.
- 🖥️ Hosts for Linux (x86_64/aarch64) and macOS (`aarch64-darwin`, `x86_64-darwin`).
- 👥 Per-user overrides with shared profiles so teams can reuse common pieces without pulling extra packages.
- 🪟 Role-aware profiles (e.g. `desktop`, `server`, `virtualisation`) assembled per host.
- 🏠 Host-aware Home Manager outputs exposed as `homeConfigurations."hosts/<host>/<user>"`.
- 🧰 Shared module library for services (e.g. `mihomo`, `vfio`) and desktop components.

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

Activate a system or home configuration using flake references.

```bash
# NixOS / nix-darwin host
sudo nixos-rebuild switch --flake .#tank
# or
darwin-rebuild switch --flake .#m3max

# Home Manager for a host/user pair
home-manager switch --flake .#"hosts/H610/hank"
```

> 🔁 Every host entry is defined in `nixos/hosts/<name>/default.nix`, where you can select shared profiles, external modules, and user-specific overrides.

## 📄 License

MIT
