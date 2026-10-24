# Rex appearance migration

On 2026-10-24, Hank's Ghostty settings were migrated to Rex Beta 0.1.0
(build 1408) on praxic. `home/users/hank/rex.nix` applies the same preferences
to Hank's macOS GUI homes, using the evaluated Ghostty settings as the source
for the dark theme and fonts. The light theme is
[Kanso Pearl](https://github.com/webhooked/kanso.nvim/blob/main/extras/ghostty/kanso-pearl),
as requested. The appearance selector remains under the user's control.

Rex's [Lua configuration](https://www.superlogical.com/rex/docs/customize/config)
controls keys and actions. Appearance lives separately in the
`com.superlogical.rex` user defaults domain. Home Manager's
`targets.darwin.defaults` manages the supported preferences; the activation
fragment handles only the custom-theme JSON stored as `NSData`, which that
module cannot encode. It preserves other custom themes and unrelated settings.
No original application configuration file is copied into this repository.

| Ghostty setting | Rex migration |
| --- | --- |
| Kanso background, foreground, cursor, selection and ANSI 0–15 | Kanso Zen custom theme; exact sRGB values |
| Light appearance | Kanso Pearl; exact upstream Ghostty colors |
| ANSI 16–255 | Standard xterm palette, matching Ghostty |
| RecMonoSmCasual Nerd Font Mono, size 15 | Terminal font and size |
| Menlo, then PingFang SC | Ordered fallback fonts |
| Bar cursor, no blinking | Bar, blink interval 0; applications may still change its shape |
| `macos-option-as-alt = true` | Both Option keys send Alt |
| Tabs in the title bar | Rex already uses horizontal tabs; kept its existing setting |
| Opacity 0.85, blur radius 20 | No numeric equivalent found in this build's settings; Rex glass controls differ |
| Cursor thickness 250%, `font-thicken` | No equivalent found in this build's settings |
| Alt+i quick terminal | No matching global quick-terminal action found; not rebound to another action |
| Shell integration, clipboard policy, click-to-move, TERM, auto-update | Application-specific behavior; no unverified mapping added |

The initial theme was imported using Rex's Settings → Themes → Import with
`~/.config/ghostty/themes/kanso`, then named Kanso Zen. Kanso Pearl was imported
from the upstream Ghostty theme. Their IDs are retained by the Nix module so
activation updates those themes rather than creating duplicates.
The live font, fallback order, cursor, and Option preferences were changed in
Rex settings. Updating defaults through Home Manager on another Mac may require
reopening the Rex client before its appearance refreshes.

The generated themes were compared against both Rex imports, including all
256 palette entries. Repeated theme activation was verified to preserve other
preferences and themes and to produce the same data. All eleven managed
preferences matched the live app. No full Home Manager switch was run for the
initial migration; appearance was applied directly in Rex.

Use `just hm-dry <host> hank` to review a home generation, and
`just hm <host> hank` when activating it. A system rebuild does not apply this
module. Rex remains separately installed; this module does not install the app.

## Tmux keys

`home/modules/rex` generates `init.lua` through `programs.rex.bindings` and
`extraConfig`. Hank's bindings are in `home/users/hank/rex.nix`. Home activation
checks the file and reloads an already-running local Rex server.

Each sequence starts with **Ctrl-b**, then the key below. Escape cancels a
pending prefix. **Ctrl-b Ctrl-b** sends a literal Ctrl-b to the terminal,
including to a nested remote tmux.

| Key after Ctrl-b | Action |
| --- | --- |
| h / j / k / l | Focus left / down / up / right, wrapping at an edge |
| H / J / K / L | Swap with the neighboring pane; focus follows the original pane |
| Arrow keys | Move a divider in that direction by 5% of its split |
| % / " | Split right / down |
| c | New tab |
| n / p / 1–9 | Next / previous / numbered tab |
| , | Rename tab |
| < / > | Move the current tab backward / forward |
| z | Toggle pane zoom |
| o | Focus next pane |
| x | Close pane using Rex's normal close behavior |
| ! | Move pane into a new tab |
| s / $ | Choose / rename session |
| : | Rex command palette |
| d | Close the client window; sessions remain on the server |
| r | Check/reload Rex configuration |

This uses Rex's native key sequences. Its resize unit is a percentage, rather
than tmux's five rows or columns, and it does not reproduce tmux's 300 ms
repeat-key table. Press Ctrl-b for each new sequence. Existing macOS shortcuts
remain available. Tmux's last-window Tab, copy-mode, scratch popup, resurrect,
thumbs and agent-sidebar bindings are not mapped to unrelated actions.

Validated on Rex 1408 with 39 loaded bindings and one custom action, without
keymap diagnostics. Live keyboard checks covered both split directions,
directional focus, swapping unequal panes while preserving split IDs and
ratios, resizing from 50% to 55%, zoom toggling, tab creation/navigation and tab
reordering. The generated file was linked and reloaded directly; no full home
switch was needed. The test session was retained after the user began using it.
