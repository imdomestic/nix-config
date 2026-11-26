# Fendada's Pi

Home Manager manages Pi and model metadata, merges declared UI preferences into writable settings, and installs the UI dependencies in the Nix store. Credentials remain in SOPS; neither Windows `auth.json` nor sessions are copied.

Windows baseline (2026-11-26): CLIProxy / `gpt-6-astra`, medium thinking, `midnight-code`, Open TUI 0.4.4, and better-render 0.5.0. `framed-code.patch` contains the two local Windows renderer changes against the published 0.5.0 package. The original dependency licenses are retained in the installed packages. Mermaid is bundled to avoid runtime npm installation; Linux native resvg libraries are patched for NixOS.

- `default.nix`: models, defaults, activation.
- `midnight-code.nix`, `open-tui.nix`: theme and UI preferences.
- `ui.nix`, `ui/package{,-lock}.json`: pinned UI dependency build (npm mirror URLs plus integrity hashes).

Apply on NixOS WSL from the repository root:

```sh
home-manager switch --flake '.#fendada@7945hx-wsl'
```

Pi's wrapper appends localhost and `.inner.imdomestic.com` to both proxy bypass variables, preserving existing entries. This keeps WSL's Windows proxy from returning 502 for private model endpoints, without changing proxy settings for other programs.

Other Fendada dev-tier homes inherit these preferences too. Windows paths and Windows native node modules are not used. Re-activation reapplies declared preferences while preserving unrelated runtime fields.
