# Rex

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

Kanso Zen and Kanso Pearl were first imported through Rex's Settings → Themes →
Import; the Nix module keeps their IDs so activation updates those themes
rather than creating duplicates. Updating defaults through Home Manager on
another Mac may require reopening the Rex client before its appearance refreshes.

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

## Copy mode

**Ctrl-b [** runs the `copy_mode` action from `home/hank/modules/rex/default.nix`. It
opens a floating layer over the focused pane (over the whole window when the
pane is zoomed) and shows the pane's scrollback, captured with
`rex capture --unwrap --trim`, in a read-only nvim with the cursor on the last
line. A floating layer is used instead of a split so the original pane is not
resized and its program does not redraw. In visual mode `y` copies the
selection through OSC 52, which Rex writes to the macOS clipboard, and leaves,
like tmux's `copy-selection-and-cancel`. `q` leaves without copying; the layer
closes and the script focuses the pane again with `rex focus`. All other nvim
motions and searches work as usual. Colors are not kept.

From 2026-10-25 to 2026-11-12 the layer covered the whole window instead,
working around a Rex 1443 bug that drew no floating layer starting right of
the window's left edge; Rex 1889 fixed it. What misled: everything the server
reported was right (the layer's bounds and size, its captured screen), so only
looking at the window showed the fault. After the blind quits that bug caused,
the keyboard did not come back to the pane, so the script still refocuses it
with `rex focus` as a safety net.

Pane rects in `rex.session.view` are fractions of the window even inside a
floating layer, so a pane's rect can be used as layer bounds anywhere. Opening
the layer ends a pane's zoom, so the action passes the zoom state to the
script, which zooms the pane again on exit, before the layer closes. Run
against a just-created tab that was never shown, a yank did not reach the
clipboard.

## Shell integration

Rex reads OSC 7 (working directory) and OSC 133 (prompt and command marks),
but does not inject a shell integration, and Ghostty's own loads only inside
Ghostty. `rex.nix` adds a small zsh hook, active only when `TERM_PROGRAM` is
`rex`: it reports the directory and marks prompt start, input start, command
start and exit status. Without the hook `rex block call pwd` returns `{}`. The
prompt marks are what Jump to Previous/Next Prompt and the program status
protocol's prompt-time cleanup rely on; those were not yet checked in the app.

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
handshake ([iOS data handshake](../incidents.md#rex-ios-data-handshake)).
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

## Login server on Linux {#login-server}

Superlogical invited Hank to the Rex Linux alpha on 2026-10-31. The `rex` flake
input follows the snapshot channel
(`https://pkgs.superlogical.com/rex/nix/snapshot.tar.gz`). The package host
names a fixed release URL in a `Link: rel="immutable"` header, and
`flake.lock` records that URL, so `just upp rex` moves to the newest snapshot.
The flake packages the prebuilt binary; `inputs.nixpkgs.follows` links it
against this repo's glibc and pam.

`system/modules/rex-login-server.nix`, loaded by the server profile and on
wherever the host has a `tsName` (every tailnet server: encore, gizmo, h310,
h610, r2s, r5s, r6s, rpi4, seraph, taipan, tank, tokyo), imports the flake's
NixOS module and runs `rex login-server` as root.
It listens on `tailnet://:7297` (opened on `tailscale0`), asks the host's
tailscaled who each caller is, and starts or reuses a Rex server for the
matching operating system account, as that account. Every account in the
host's registry entry is listed in `/etc/rex/accounts.jsonc`, reachable only
by the headscale login of the same name (`tailscale:<account>@imdomestic.com`),
which is also that login's default account. Each person therefore sees only
their own sessions, without naming an account:
`http://tank.inner.imdomestic.com:7297`. A login with no account of its name
on the host, such as `max`, is refused. Giving someone access to another host
means adding their account to its `users` in `host.nix`.

The module also puts `rex` in the system profile, its `xterm-rex` terminfo
entry, and its ssh guard in `/etc/ssh/ssh_config` for every account. On
logind hosts an account's server is that person's ordinary personal server,
so `rex` in an ssh shell on tank shows the same sessions as the app.

A login with no account of its name on the host is answered "not in the
account policy", and asking for another person's account is refused with 403.
An old Rex client can reach its account and start the shell but never complete
the terminal data connection
([iOS data handshake](../incidents.md#rex-ios-data-handshake)); update the app.
