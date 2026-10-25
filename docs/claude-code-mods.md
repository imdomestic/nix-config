# Claude Code mods

A Claude Code mod is a plugin whose hooks module (TypeScript the engine runs)
changes Claude Code's own interface. Hank's live in `pkgs/claude-<name>/mod/`;
the package's output is the plugin folder, and
`home/hank/modules/claude-code/default.nix` names it in
`CLAUDE_CODE_PLUGIN_DIRS`, which Claude Code reads as it reads `--plugin-dir`.
A shell started after `just hm <host> hank` has the new folder; a running
Claude Code keeps what it loaded.

Not a marketplace install: a folder marketplace plus `claude plugin install`
records the plugin in `~/.claude/plugins/` and in `enabledPlugins` of
`settings.json`, and neither is managed here (see the statusline note in
`home/hank/default.nix`). The variable keeps everything in the home
generation. What it costs: Claude Code treats the folder as one under
development. It watches it (a store path never changes) and tries to lay its
editor types in `.claude-plugin/types/`, which fails on the read-only store
path with one `type root of inline-media not laid: EACCES` line in the debug
log and nothing else.

## inline-media

What it draws, on the terminal surface:

- Display math, `$$…$$` or `\[…\]` on lines of their own, as pictures under
  the part of the reply the engine draws. Inline math becomes Unicode
  (`$x^2$` → x², `\frac{a}{b}` → a/b).
- A reply line holding only a local `![alt](/path)`, as the picture. Remote
  pictures stay text.
- Pictures that Read returned, under the collapsed `Read N files` row.
- Pasted pictures, under the prompt that carried them.

`render/render.mjs` makes every PNG: MathJax and resvg from pi-math's
`node_modules`, which the package links beside it; patchShebangs points its
`#!/usr/bin/env node` at the store's node. A PNG up to 1.5 MB is drawn as it
is; anything else goes through resvg, at most 1000 px a side: PNG, JPEG, GIF
and SVG (on white, with system fonts). resvg-js 2.6.2 does not decode WebP;
such a picture shows its alt text and the reason.

Pasted pictures are matched to the prompt row by its text. The row is drawn
before it is stored, so its first draw finds none; a `session.append` hook
keeps the pictures as the prompt is appended and has the rows drawn again.
Rows from before a reload or a `--continue` are found in
`$.session.messages({ as: 'api' })`, the conversation as the next request
carries it. Pictures pasted before a compaction are gone from it, the summary
standing in their place, so their rows show none.

Limits:

- Pictures need a terminal Claude Code trusts with kitty images: kitty 0.28 or
  later, Ghostty, or Rex through `CLAUDE_CODE_FORCE_TERMINAL_IMAGES`
  ([rex.md](rex.md#claude-code-pictures)). Anywhere else the alt text shows.
- Formula sizes assume cells twice as tall as wide (Rex's 18×36 at 2x).
- The formula color follows the theme's name: Kanso Pearl's foreground when it
  contains `light`, Kanso Zen's otherwise.
- The main screen never redraws a printed row, so a reply waits for its
  pictures instead of swapping them in later.

### Developing

`claude plugin test pkgs/claude-inline-media/mod` runs the tests; the engine
lays its types in `.claude-plugin/types/` (git ignores them), after which
`tsc -p pkgs/claude-inline-media/mod` type-checks. `claude --plugin-dir
pkgs/claude-inline-media/mod` reloads the source folder on every save, but
render.mjs then finds no `node_modules` beside it: start that Claude Code
with `NODE_PATH` set to pi-math's (the `node_modules` link inside the folder
`CLAUDE_CODE_PLUGIN_DIRS` names leads there), and with
`CLAUDE_CODE_PLUGIN_DIRS` unset, or the installed copy loads beside it.

Verified on 2026-10-25 on praxic (Rex 1443, Claude Code 2.1.310): the nine
tests pass; a picture pasted into a fresh session showed under its prompt at
once; the store build, loaded through `CLAUDE_CODE_PLUGIN_DIRS` in an
interactive session, drew a display formula and an image line as kitty
placeholders. Read previews and pasted pictures were checked by eye in the
development copy the store build was made from.

What misled, for pasted pictures: the first version joined a message's text
blocks into one key, which never matched. The session transcript (the
`.jsonl`) stores a pasted prompt as its text and its image, so it looked
right; the API form merges that turn's `<system-reminder>` blocks into the
same message as further text blocks. Blocks are now matched one by one.
After that fix the picture of the prompt that tested it did show, but only
because the mod's reload redrew the transcript; the next pasted picture did
not, its row having been drawn before the conversation held it. Hence the
`session.append` hook.
