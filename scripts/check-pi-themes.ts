import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getMarkdownTheme, highlightCode, initTheme, type ExtensionAPI, type ThemeBg, type ThemeColor, type ThemeToken } from "@earendil-works/pi-coding-agent";
import { colorToHex, Markdown, stripTerminalSequences, visibleWidth } from "@earendil-works/pi-tui";

const backgrounds = new Set([
  "selectedBg", "searchMatchBg", "userMessageBg", "customMessageBg",
  "toolPendingBg", "toolSuccessBg", "toolErrorBg",
]);
const variants = {
  "evergarden-fall": { appearance: "dark", pageBg: "#232a2e", text: "#f8f9e8", keyword: "#f57f82" },
  "evergarden-lunar": { appearance: "dark", pageBg: "#1c1d29", text: "#f7f1e6", keyword: "#eb7f86" },
  "evergarden-spring": { appearance: "dark", pageBg: "#2b3438", text: "#f8f9e8", keyword: "#f57f82" },
  "evergarden-summer": { appearance: "light", pageBg: "#f5efe6", text: "#2b3034", keyword: "#c58687" },
  "evergarden-winter": { appearance: "dark", pageBg: "#1e2528", text: "#f8f9e8", keyword: "#f57f82" },
  "kanso-ink": { appearance: "dark", pageBg: "#14171d", text: "#c5c9c7", keyword: "#8992a7" },
  "kanso-mist": { appearance: "dark", pageBg: "#22262d", text: "#c5c9c7", keyword: "#8992a7" },
  "kanso-pearl": { appearance: "light", pageBg: "#f2f1ef", text: "#22262d", keyword: "#624c83" },
  "kanso-zen": { appearance: "dark", pageBg: "#090e13", text: "#c5c9c7", keyword: "#8992a7" },
};
// Freeze the complete original JSON across the split, not just a few selected colors.
const originalHashes: Record<string, string> = {
  "evergarden-winter": "43297ff5759c75c0339c3ce75ffad88ac0983b83f6fa0156e30162be7f0b3e26",
  "kanso-zen": "69551e20728aa29ae5d946cab27853dc4c3eb027d0fcbafd730a6f16a6947b04",
};
function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((offset) => {
    const channel = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(fg: string, bg: string): number {
  const a = luminance(fg), b = luminance(bg);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

export default function (pi: ExtensionAPI) {
  pi.on("session_start", (_event, ctx) => {
    try {
      const agent = process.env.PI_CODING_AGENT_DIR;
      assert(agent);
      const documents = JSON.parse(readFileSync(join(agent, "themes.json"), "utf8"));
      assert.deepEqual(Object.keys(documents).sort(), Object.keys(variants).sort());

      for (const [name, document] of Object.entries(documents) as [keyof typeof variants, any][]) {
        const expected = variants[name];
        assert.equal(document.name, name);
        assert.equal(document.export.pageBg.toLowerCase(), expected.pageBg);
        assert.equal(document.colors.text.toLowerCase(), expected.text);
        assert.equal(document.colors.syntaxKeyword.toLowerCase(), expected.keyword);
        if (originalHashes[name]) {
          const keys = [...Object.keys(document), ...Object.keys(document.colors), ...Object.keys(document.export)].sort();
          const hash = createHash("sha256").update(JSON.stringify(document, keys)).digest("hex");
          assert.equal(hash, originalHashes[name], `${name}: original theme changed during the split`);
        }
        // RPC cannot switch UI themes, but the public initializer uses Pi's real loader.
        initTheme(name);
        const theme = ctx.ui.theme;
        assert.equal(theme.name, name, "Invalid themes must not silently fall back to system");
        assert.equal(theme.appearance, expected.appearance);
        assert.equal(theme.getColorMode(), process.env.PI_TRUE_COLOR === "0" ? "256color" : "truecolor");
        assert.equal(Object.keys(theme.colors).length, Object.keys(document.colors).length);
        for (const bg of backgrounds) {
          assert(contrast(document.colors.text, document.colors[bg]) >= 4.5, `${name}: body text has low contrast on ${bg}`);
        }
        assert(contrast(document.colors.text, document.export.pageBg) >= 4.5, `${name}: body text has low page contrast`);

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
        console.error(`${name}: all colors, ${theme.appearance} appearance, contrast, Markdown and syntax passed (${theme.getColorMode()})`);
      }
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
    ctx.shutdown();
  });
}
