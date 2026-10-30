# Rex appearance migration

On 2026-10-24, Hank's Ghostty settings were migrated to Rex Beta 0.1.0
(build 1408) on praxic. `home/hank/modules/rex/default.nix` applies the same preferences
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

## CLI path

`~/.local/bin/rex` points to the installed server's `Versions/Current` CLI.
That directory is already on Hank's PATH, so ordinary terminals can run `rex`
without a version-specific path. The app and server are not copied into Nix.

Inside Rex, `programs.zsh.initContent` restores `REX_BIN_DIR` to the front at
order 2000, after Nix and Homebrew initialization. This keeps the CLI matched
to the server that opened that terminal, including when it differs from
`Versions/Current`. `REX_BIN_DIR` is not added to `home.sessionPath`, and an
unset variable does not add an empty PATH entry. See the
[upstream PATH documentation](https://www.superlogical.com/rex/docs/automate/cli#path).

Validated in an ordinary shell and a fresh login shell started by Rex: both
resolve `rex`, and the Rex shell has `REX_BIN_DIR` as its first PATH entry.
The generated `.zshrc` and CLI link were applied directly, without a full home
switch.

## Tmux keys

`home/hank/modules/rex/module.nix` generates `init.lua` through `programs.rex.bindings` and
`extraConfig`. Hank's bindings are in `home/hank/modules/rex/default.nix`. Home activation
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
| [ | Copy mode (see below) |
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
remain available. Tmux's last-window Tab, scratch popup, resurrect,
thumbs and agent-sidebar bindings are not mapped to unrelated actions.

Validated on Rex 1408 with 39 loaded bindings and one custom action, without
keymap diagnostics. Live keyboard checks covered both split directions,
directional focus, swapping unequal panes while preserving split IDs and
ratios, resizing from 50% to 55%, zoom toggling, tab creation/navigation and tab
reordering. The generated file was linked and reloaded directly; no full home
switch was needed. The test session was retained after the user began using it.

## Copy mode

**Ctrl-b [** runs the `copy_mode` action from `home/hank/modules/rex/default.nix`. It
opens a floating layer over the whole window and shows the focused pane's
scrollback, captured with `rex capture --unwrap --trim`, in a read-only nvim
with the cursor on the last line. A floating layer is used instead of a split
so the original pane is not resized and its program does not redraw. In
visual mode `y` copies the selection through OSC 52, which Rex writes to the
macOS clipboard, and leaves, like tmux's `copy-selection-and-cancel`. `q`
leaves without copying; the layer closes and the script focuses the pane
again with `rex focus`. All other nvim motions and searches work as usual.
Colors are not kept.

Until 2026-10-25 the layer covered only the pane. Rex 1443 draws no floating
layer that starts right of the window's left edge: over a right-hand pane
(bounds `[0.6, 0, 0.4, 1]`), and in a test layer at `[0.25, 0.25, 0.25, 0.25]`,
nothing appeared, while the invisible nvim kept the keyboard and only a blind
`:q` closed it. Layers starting at the top-left corner draw normally, which is
why left-hand and zoomed panes worked. What misled: everything the server
reports was right. The layer had the pane's bounds, the app had even sized it
(63×47 for a 63-column pane, with itself as owner), and its screen captured
fine, so only looking at the window showed the fault. The 2026-10-24 check
below had the same blind spot: it compared bounds, not pixels. After those
blind quits the keyboard also did not come back to the pane, although in the
recorded run the server had refocused it; hence the explicit `rex focus`.

Verified on 2026-10-24 by running the action against a test tab through
`rex do --action`: the layer bounds matched the pane, the view ended at the
pane's last line, soft-wrapped lines were joined, and three yank-and-leave
runs put the selected line on the clipboard (`clipboard_written`, then
`child_exited`, then `block_closed`). One run against a just-created,
never-shown tab did not reach the clipboard.

## Shell integration

Rex reads OSC 7 (working directory) and OSC 133 (prompt and command marks),
but does not inject a shell integration, and Ghostty's own loads only inside
Ghostty. `rex.nix` adds a small zsh hook, active only when `TERM_PROGRAM` is
`rex`: it reports the directory and marks prompt start, input start, command
start and exit status. The directory report is verified: before the hook,
`rex block call pwd` returned `{}`; with it, a new shell reports
`file://praxic/Users/hank` and follows `cd`. The prompt marks are what Jump to
Previous/Next Prompt and the program status protocol's prompt-time cleanup
rely on; those were not yet checked in the app.

## Claude Code pictures

Claude Code 2.1.310 draws an image (a mod's `Image` element, for one) only
when the terminal answers its kitty graphics query and its XTVERSION reply
names `kitty` 0.28 or later or `ghostty`; anywhere else it draws the image's
alt text. Rex answers the query, but its XTVERSION is `rex <version>`, so
Claude Code drew text, although Rex's emulator is libghostty. On 2026-10-25 a
picture sent the way Claude Code sends one (`a=T,U=1`, kitty Unicode
placeholders) displayed correctly in a Rex pane, so the same zsh block sets
`CLAUDE_CODE_FORCE_TERMINAL_IMAGES=1`, the switch Claude Code reads in place
of that check, when `TERM_PROGRAM` is `rex`. A Claude Code started before the
variable was set keeps its own verdict until it restarts. Inside tmux in Rex,
`TERM_PROGRAM` is `tmux`, the variable is not set, and Claude Code's tmux
rules apply. The mod that draws math and pictures this way:
[claude-code-mods.md](claude-code-mods.md#inline-media).

## Opening Rex from AeroSpace

`alt-enter` asks the Rex app for a new window, which comes with a new session,
then brings Rex to the front. This needs **Remote Control** under Rex Server in
Rex's settings; without it, or when Rex is not running, the CLI call fails and
`alt-enter` only opens or raises Rex. The previous binding launched kitty,
which was not installed.

## Tailnet access on praxic {#tailnet-access}

Hank's `home/hank/praxic.nix` loads `modules/rex/tailnet-relay.nix`. Its
Home Manager launch agent, `org.nix-community.home.rex-tailnet-relay`, forwards
TCP port 7297 on the Mac's Tailscale IPv4 address to the existing Rex Unix
socket. It starts at login and restarts after exit, retrying every 30 seconds
if Tailscale is not ready. It does not start or restart Rex itself.

Connect from Rex for iOS with Tailscale enabled, using
`http://praxic.inner.imdomestic.com:7297` (currently `http://100.64.0.9:7297`).
Terminals display on iOS through this relay since the iOS app update of
2026-10-31; build 1577 had connected but never completed the terminal data
handshake ([iOS data handshake](incidents.md#rex-ios-data-handshake)).
The relay binds only the Tailscale address and accepts sources in
`100.64.0.0/10`; Tailscale encrypts the HTTP connection. As requested, every
tailnet device that network policy permits can connect. Rex sees the relay as
the local Hank user, so those devices have full access to Hank's Rex sessions,
without separate Rex authentication.

The Mac must be awake, Hank logged in, and the Rex server running. Logs are in
`~/Library/Logs/rex-tailnet-relay.log`. To inspect or restart the relay:

```sh
launchctl print gui/$(id -u)/org.nix-community.home.rex-tailnet-relay
launchctl kickstart -k gui/$(id -u)/org.nix-community.home.rex-tailnet-relay
```
