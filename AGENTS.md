# Repository Guidelines

## Project Structure & Module Organization
- Entry points: `flake.nix` and `flake.lock` declare inputs and assemble outputs. Shared helpers live under `lib/` (`mkConfigurations.nix`, `mkHomeConfigurations.nix`, `mkSystemManagerConfigurations.nix`, `mkDeployNodes.nix`).
- Hosts: `nixos/hosts/<name>/` holds `system.nix` plus `hardware-configuration.nix`; set `kind = "home"` for HM-only targets. Host registry is `nixos/hosts/default.nix`.
- Profiles & modules: reusable system modules in `nixos/modules/`, profiles in `nixos/profiles/`; macOS-specific bits in `darwin/profiles/`. Home Manager modules in `home/modules/`, shared profiles in `home/profiles/`, user tweaks in `home/users/<name>/`.
- Assets: fonts in `fonts/`, wallpapers in `wallpapers/`. License and top-level docs live at repo root.

## Build, Test, and Development Commands
- `just` lists tasks. Prefer Just recipes for consistency.
- Flake health: `just check` (or `just check-trace` for more logging) runs `nix flake check` with predefined substituters.
- Rebuild hosts: `just switch <host>` for NixOS, `just darwin <host>` for macOS. Add `--show-trace` via `just debug <host>` when diagnosing failures.
- Home Manager: `just hm <host> <user>` to apply; `just hm-dry <host> <user>` for a dry run before switching.

## Coding Style & Naming Conventions
- Nix style: two-space indentation, trailing commas, and attribute sets ordered logically; keep option names kebab-case to match upstream modules.
- Prefer small, composable modules; keep profile files focused on role composition rather than package lists.
- Format Nix with `nix fmt` or `nixpkgs-fmt` before sending a PR.

## Testing Guidelines
- Always run `nix flake check` (via `just check`) after changes to modules, profiles, or inputs.
- For host-specific changes, run `just hm-dry <host> <user>` or `just debug <host>` to catch option regressions without switching.
- Add comments sparingly to explain non-obvious options (e.g., service quirks or hardware workarounds).

## Commit & Pull Request Guidelines
- Commit messages are short and imperative (repository history favors concise verbs like “update”); use a single scope per commit.
- PRs should describe the target host(s), profiles touched, and expected outcomes. Link related issues or upstream module references when relevant.
- Include the commands you ran (e.g., `just check`, `just hm-dry <host> <user>`) and note any remaining warnings or TODOs.

## Security & Configuration Tips
- Do not embed secrets; reference paths or environment variables and prefer `age`/`sops` managed files when needed.
- When adding external inputs, pin them in `flake.nix` with clear names and update policies; document why the input is needed in a nearby comment.
