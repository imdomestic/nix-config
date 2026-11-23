# Linux desktop applications: Flatpak

## Policy and the 268v baseline

Use per-user Flathub applications for browsers, chat, media and other standalone
GUI applications. Keep the desktop/session and host-management stack native.
This follows hank's existing 268v setup, rather than moving macOS apps or adding
one shared application preference list for every account.

- `system/profiles/desktop.nix` already enables `services.flatpak` by default.
  `9950x` (WSLg, `gui` without `desktop`) and `tank` (a GNOME session but no
  `desktop` role) explicitly enable it. WSLg also needs a system GTK portal;
  enabling Flatpak without `xdg.portal.enable` fails NixOS assertions.
- Each account imports `inputs.nix-flatpak.homeManagerModules.nix-flatpak` in
  its own home. Home Manager remains standalone, never a system module.
- Common apps belong in that account's Linux GUI profile/module. Host-only
  additions stay in `home/<account>/<host>.nix`: Bambu Studio on encore,
  Firefox/Clapper on gpd, Chromium/Firefox on x470, Clapper on tank.
- Use the standard `flathub` remote at
  `https://dl.flathub.org/repo/flathub.flatpakrepo`. Keep
  `uninstallUnmanaged = false`: manually installed apps/remotes are not removed.
  These are the existing nix-flatpak v0.7.0 defaults, now explicit.
- Match hank's `update.onActivation = true` and daily automatic updates.
  Flatpak applications update independently of `flake.lock` and Nix generations.
- Keep linwhite's `en;zh` Flatpak language activation hook (originally for
  Bambu Studio). Preserve the same language support in fendada's own module.
  Hank's baseline does not impose a language override.
- Hank's `zen` wrapper uses `flatpak run --file-forwarding` with `@@u` arguments;
  both home and systemd user `BROWSER` point to it. HTML and HTTP(S) MIME
  defaults use `app.zen_browser.zen.desktop`. None of this changes.
- Keep hank's Zen `MOZ_ENABLE_WAYLAND=1` override and WeChat's Wayland socket
  plus `QT_QPA_PLATFORM=wayland;xcb`. Do not blanket-force an IME or expose
  additional files/devices to every sandbox. Existing fcitx5/IBus and portals
  stay native. Linwhite/fendada's Hyprland browser shortcut now runs
  `flatpak run com.google.Chrome`, not an interpolated nixpkgs Chrome path.

There is no `home/hank/268v.nix`: the registry's `desktop`/`gui` roles select
`home/hank/profiles/gui-linux.nix`. Encore's hank host file only handles its
GNOME power-settings conflict. Tank intentionally does not import the common
GUI app module: it gets Clapper only, without adding Zen/QQ/WeChat/Spotify.
Fendada's pre-existing borrowed encore desktop/workflow is retained; its new
Flatpak application list and language hook are account-local, not imported
from linwhite's application profile.

## Migration inventory

The audit covered all accounts (`fendada`, `genisys`, `hank`, `kenneth`,
`linwhite`, `nix`), explicit `home.packages`, system/user package lists,
`programs.*` browser declarations and launcher references under `home/`,
`hosts/` and `system/`.

Every ID below was checked against the live Flathub AppStream API on
2026-11-23: HTTP 200, matching `id` and application `name`. Links are the actual
verification endpoints, not inferred IDs.

| Accounts / hosts | Previous nixpkgs application | Verified Flathub application |
| --- | --- | --- |
| linwhite: 9950x, encore, gpd; fendada: encore | `qq` (pinned deb override) | [com.qq.QQ](https://flathub.org/api/v2/appstream/com.qq.QQ) — Linux QQ |
| same | `google-chrome` | [com.google.Chrome](https://flathub.org/api/v2/appstream/com.google.Chrome) — Google Chrome |
| same | `spotify` | [com.spotify.Client](https://flathub.org/api/v2/appstream/com.spotify.Client) — Spotify |
| same | `prismlauncher` | [org.prismlauncher.PrismLauncher](https://flathub.org/api/v2/appstream/org.prismlauncher.PrismLauncher) — Prism Launcher |
| same | `zathura` | [org.pwmt.zathura](https://flathub.org/api/v2/appstream/org.pwmt.zathura) — Zathura |
| same | `sioyek` (listed twice) | [com.github.ahrm.sioyek](https://flathub.org/api/v2/appstream/com.github.ahrm.sioyek) — Sioyek |
| same | `upscayl` | [org.upscayl.Upscayl](https://flathub.org/api/v2/appstream/org.upscayl.Upscayl) — Upscayl |
| linwhite: gpd; hank: x470 | `firefox` / system `programs.firefox` | [org.mozilla.firefox](https://flathub.org/api/v2/appstream/org.mozilla.firefox) — Firefox |
| linwhite: gpd; hank: tank | `clapper` | [com.github.rafostar.Clapper](https://flathub.org/api/v2/appstream/com.github.rafostar.Clapper) — Clapper |
| hank: x470 | system `programs.chromium` | [org.chromium.Chromium](https://flathub.org/api/v2/appstream/org.chromium.Chromium) — Chromium Web Browser |

Existing Flatpak apps, also re-verified (not newly added):

| Account / scope | Application |
| --- | --- |
| hank: Linux GUI profile | [com.tencent.WeChat](https://flathub.org/api/v2/appstream/com.tencent.WeChat), [app.zen_browser.zen](https://flathub.org/api/v2/appstream/app.zen_browser.zen), QQ and Spotify above |
| linwhite/fendada: encore | [com.bambulab.BambuStudio](https://flathub.org/api/v2/appstream/com.bambulab.BambuStudio) |

Kenneth has a Darwin GUI profile only; its Sioyek remains native. The
`gui/common.nix` Sioyek declarations for hank and linwhite are also currently
imported only by their Darwin GUI modules. Genisys has no applications, and
nix has CLI tools plus Kitty, not standalone desktop apps to migrate.

No explicit Linux declarations of bilibili, Telegram, Discord, OBS Studio,
GIMP, Blender, VLC, mpv, Thunderbird or LibreOffice were found. This migration
does not install applications that an account did not already select.
The pinned QQ amd64 deb URL in the old override returned HTTP 404 when checked
on 2026-11-23. That URL/hash override and duplicate Linux Sioyek entries are
removed. No application-specific unfree allow-list or overlay remains to
remove; global unfree settings are still used by drivers/Steam/other software.

## What stays native, and why

| Native items | Reason |
| --- | --- |
| GNOME/session components and their standard bundled utilities; Hyprland, Waybar, rofi/vicinae, mako, polkit agent | Desktop/session infrastructure; retain the same GNOME baseline as 268v, not a new replacement desktop |
| fcitx5/IBus, configuration tools, portals, fonts, themes, cursor, `nwg-look` | Host input and desktop integration |
| `pavucontrol`, `playerctl`, WirePlumber, `grimblast`, `wl-clipboard`, brightness tools | Host audio, screenshots, clipboard and compositor controls |
| Ghostty, WezTerm, Kitty, Neovim/nixvim and CLI/development tools | Same native terminal/editor/toolchain boundary as 268v; Neovim image conversion and headless browser dependencies are not desktop application installs |
| virt-manager, virt-viewer, QEMU/SPICE stack | Host libvirt/VM management; 268v itself retains native `programs.virt-manager` for its Windows VM |
| Steam, gamescope, `steam-run`, `steamcmd` | Existing NixOS gaming session, capabilities, 32-bit graphics, controller/firewall and server/runtime integration, not just an isolated user app |
| `corectrl`, radeontop, btop/ROCm/CUDA, nvtop and hardware diagnostics | Host GPU controls/monitoring rather than sandboxed user applications |
| Darwin-only Sioyek, Kazumi, Rex, Safari MRU, AeroSpace/macmon and Homebrew apps | Outside Linux/Flatpak scope; keep Darwin evaluator and preferences unchanged |

## Activation and verification

This change does not deploy anything. After merging:

1. Deploy the **system first** on `tank` and `9950x` to provide Flatpak (and
   WSLg's portal); other desktop hosts already provide it. x470 also needs
   its system update to remove the old system-wide browser packages.
2. Activate each affected standalone home (`just hm <host> <account>`), or
   let an eligible server's `home-sync` do so. A system switch alone never
   activates homes. Desktop-only/GUI-only hosts do not acquire a home-sync
   timer from this change.
3. Initial Flatpak/runtime downloads need network access, disk space and time.
   Inspect `systemctl --user status flatpak-managed-install.service` and
   `flatpak --user list`; successful Nix evaluation is not a runtime GUI test.
   A fresh login may be needed for exported desktop entries/session paths.
4. Back up and migrate existing browser profiles, QQ login data, Minecraft
   instances and app settings as needed into `~/.var/app/<id>/`; switching
   packaging does not automatically import native application data. New
   sandboxes may require re-login and portal file selection. Test Chinese
   input, GPU acceleration and file access in the actual desktop session.
5. Old native binaries disappear from the next active home/system, but older
   Nix generations retain rollback closures until normal garbage collection.
   Unmanaged/system-wide Flatpaks are deliberately not automatically removed.

Verification commands (one configuration per process, as required by AGENTS):

```sh
EVAL_JOBS=3 bash scripts/eval.sh
nix fmt -- --check .
nix run --inputs-from . nixpkgs#deadnix -- -L --fail .
```

Use `.activationPackage.drvPath` for standalone homes and
`.config.system.build.toplevel.drvPath` for systems. No private-input override
or lock-file update is part of this migration.
