import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getMarkdownTheme, highlightCode, initTheme, type ExtensionAPI, type ThemeBg, type ThemeColor, type ThemeToken } from "@earendil-works/pi-coding-agent";
import { colorToHex, Markdown, stripTerminalSequences, visibleWidth } from "@earendil-works/pi-tui";

const backgrounds = new Set([
  "selectedBg", "searchMatchBg", "userMessageBg", "customMessageBg",
  "toolPendingBg", "toolSuccessBg", "toolErrorBg",
]);

export default function (pi: ExtensionAPI) {
  pi.on("session_start", (_event, ctx) => {
    try {
      const agent = process.env.PI_CODING_AGENT_DIR;
      assert(agent);
      const documents = JSON.parse(readFileSync(join(agent, "themes.json"), "utf8"));
      assert.deepEqual(Object.keys(documents).sort(), ["evergarden-winter", "kanso-zen"]);

      for (const [name, document] of Object.entries(documents) as [string, any][]) {
        // RPC cannot switch UI themes, but the public initializer uses Pi's real loader.
        initTheme(name);
        const theme = ctx.ui.theme;
        assert.equal(theme.name, name, "Invalid themes must not silently fall back to system");
        assert.equal(theme.appearance, "dark");
        assert.equal(Object.keys(theme.colors).length, Object.keys(document.colors).length);

        for (const [token, expected] of Object.entries(document.colors) as [ThemeToken, string][]) {
          assert.match(expected, /^#[0-9a-f]{6}$/i);
          assert.equal(colorToHex(theme.colors[token]).toLowerCase(), expected.toLowerCase(), `${name}: ${token}`);
          const styled = backgrounds.has(token)
            ? theme.bg(token as ThemeBg, "颜色 check")
            : theme.fg(token as ThemeColor, "颜色 check");
          assert.equal(stripTerminalSequences(styled), "颜色 check");
          assert(styled.includes("\x1b["), `${name}: ${token} did not produce ANSI colors`);
        }
        for (const color of Object.values(document.export)) assert.match(color as string, /^#[0-9a-f]{6}$/i);

        const highlighted = highlightCode('const value = "hello"; // comment', "typescript").join("\n");
        assert(highlighted.includes(theme.getFgAnsi("syntaxKeyword")));
        assert(highlighted.includes(theme.getFgAnsi("syntaxString")));
        for (const width of [80, 24]) {
          const markdown = new Markdown("# Theme check\n\n中文 **text**, `code` and [link](https://pi.dev).\n\n```ts\nconst value = 1;\n```", 0, 0, getMarkdownTheme());
          assert(markdown.render(width).every((line) => visibleWidth(line) <= width));
        }
        console.error(`${name}: all colors, Markdown and syntax highlighting passed (${theme.getColorMode()})`);
      }
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
    ctx.shutdown();
  });
}
