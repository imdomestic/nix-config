import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { highlightCode, initTheme, ToolExecutionComponent, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { stripTerminalSequences, Text, visibleWidth } from "@earendil-works/pi-tui";

const before = 'const value = "old 中文🙂";\nconst unchanged = 1;';
const after = 'const value = "new 中文🙂";\nconst unchanged = 1;';
const diff = `@@ -1,2 +1,2 @@\n-${before.split("\n")[0]}\n+${after.split("\n")[0]}\n ${before.split("\n")[1]}`;

export default function (pi: ExtensionAPI) {
  pi.on("session_start", async (_event, ctx) => {
    const savedOverride = process.env.DIFF_THEME;
    let restoreCache: (() => void) | undefined;
    let failed = false;
    try {
      delete process.env.DIFF_THEME;
      const packagePath = process.env.PI_CC_DIFF_PACKAGE;
      const agent = process.env.PI_CODING_AGENT_DIR;
      assert(packagePath && agent);
      const root = `${packagePath}/extensions/renderer/tool/diff`;
      const { createCodeLineHighlighter, createCodeBlockHighlighter, resolveLanguageFromPath } = await import(`${root}/diff-highlight.ts`);
      const { parseDiff } = await import(`${root}/diff-parse.ts`);
      const { renderEditDiffResult, renderWriteDiffResult } = await import(`${root}/diff-renderer.ts`);
      const { DEFAULT_TOOL_DISPLAY_CONFIG } = await import(`${root}/index.ts`);
      const { shikiHighlightCache } = await import(`${root}/shiki-highlight.ts`);
      const documents = JSON.parse(readFileSync(join(agent, "themes.json"), "utf8"));
      const entries = parseDiff(diff).entries.filter((entry: any) => entry.kind === "line");
      const config = { ...DEFAULT_TOOL_DISPLAY_CONFIG, writeDiffCollapsedLines: 24 };

      // A cache hit must not hide the bug: even warm Shiki colors must be opt-in.
      const originalGet = shikiHighlightCache.get;
      let requests = 0;
      shikiHighlightCache.get = () => { requests++; return undefined; };
      restoreCache = () => { shikiHighlightCache.get = originalGet; };
      for (const name of Object.keys(documents)) {
        initTheme(name);
        const theme = ctx.ui.theme;
        assert.equal(theme.name, name);
        assert.equal(theme.getColorMode(), process.env.PI_TRUE_COLOR === "0" ? "256color" : "truecolor");
        const highlighter = createCodeLineHighlighter("typescript", theme, entries);
        const highlighted = entries.map((entry: any) => highlighter(entry.content, entry)).join("\n");
        assert(highlighted.includes(theme.getFgAnsi("syntaxKeyword")), `${name}: diff keyword color`);
        assert(highlighted.includes(theme.getFgAnsi("syntaxString")), `${name}: diff string color`);
        const block = createCodeBlockHighlighter(after, "typescript", theme);
        assert.deepEqual(block().map(stripTerminalSequences), after.split("\n"));
        assert.equal(requests, 0, "Default diff/code blocks must not be recolored asynchronously by Shiki");

        assert.equal(resolveLanguageFromPath("@home/example.NIX"), "nix");
        assert.equal(resolveLanguageFromPath("example.ts"), "typescript");
        const nixDiff = '@@ -1 +1 @@\n-let value = "old"; in value\n+let value = "new"; in value';
        const nixEntries = parseDiff(nixDiff).entries.filter((entry: any) => entry.kind === "line");
        const nix = createCodeLineHighlighter(resolveLanguageFromPath("example.nix"), theme, nixEntries);
        assert(nix(nixEntries[0].content, nixEntries[0]).includes(theme.getFgAnsi("syntaxKeyword")), `${name}: Nix diff is not highlighted`);
        assert(nix(nixEntries[0].content, nixEntries[0]).includes(theme.getFgAnsi("syntaxString")));

        for (const diffViewMode of ["auto", "unified", "split"]) {
          const display = { ...config, diffViewMode };
          for (const expanded of [false, true]) {
            const options = { expanded, filePath: "example.ts" };
            const components = [
              renderEditDiffResult({ diff }, options, display, theme, ""),
              renderWriteDiffResult(after, { ...options, previousContent: before, fileExistedBeforeWrite: true }, display, theme, ""),
              renderWriteDiffResult(after, { ...options, fileExistedBeforeWrite: false }, display, theme, ""),
            ];
            for (const component of components) {
              for (const width of [1, 12, 42, 120, 180, 42]) {
                const lines = component.render(width);
                assert(lines.every((line: string) => visibleWidth(line) <= width), `${name}: diff exceeded ${width} columns`);
                if (width >= 120) {
                  const output = lines.join("\n");
                  assert(output.includes(theme.getFgAnsi("syntaxKeyword")), `${name}: rich diff keyword color`);
                  assert(output.includes(theme.getFgAnsi("syntaxString")), `${name}: rich diff string color`);
                  assert(output.includes("\x1b[48;"), `${name}: change backgrounds disappeared`);
                }
                const snapshot = [...lines];
                component.invalidate();
                assert.deepEqual(component.render(width), snapshot, `${name}: repaint changed diff content`);
              }
            }
          }
        }
        assert.equal(requests, 0);
        console.error(`${name}: edit, write, Nix, split/unified, wrap and repaint passed (${theme.getColorMode()})`);
      }

      // Exercise Pi's actual theme-change invalidation on the same tool component.
      const toolDefinition: any = {
        name: "edit", renderShell: "self", renderCall: () => new Text("Edit example.ts", 0, 0),
        renderResult(result: any, options: any, theme: any) {
          return renderEditDiffResult(result.details, { ...options, filePath: "example.ts" }, config, theme, "");
        },
      };
      const tool = new ToolExecutionComponent("edit", "theme-switch", { path: "example.ts" }, { showImages: false }, toolDefinition, { requestRender() {} } as any);
      tool.updateResult({ content: [{ type: "text", text: "Edited" }], details: { diff } } as any);
      tool.setExpanded(true);
      let previous: string | undefined;
      for (const name of ["evergarden-winter", "kanso-zen", "kanso-pearl", "evergarden-winter"]) {
        initTheme(name);
        tool.invalidate();
        const output = tool.render(180).join("\n");
        assert(output.includes(ctx.ui.theme.getFgAnsi("syntaxKeyword")), `${name}: old diff retained its previous theme`);
        if (previous) assert.notEqual(output, previous);
        previous = output;
      }
      const huge = "x".repeat(32_001);
      assert.deepEqual(createCodeBlockHighlighter(huge, "typescript", ctx.ui.theme)(), [huge]);
      assert.deepEqual(createCodeBlockHighlighter(after, undefined, ctx.ui.theme)(), after.split("\n"));
      assert.equal(requests, 0);
      restoreCache();
      restoreCache = undefined;

      // Preserve the documented explicit override and its asynchronous repaint.
      process.env.DIFF_THEME = "github-dark";
      let changed!: () => void;
      const ready = new Promise<void>((resolve) => { changed = resolve; });
      const override = createCodeBlockHighlighter(after, "typescript", ctx.ui.theme, changed);
      const first = override();
      assert.deepEqual(first, highlightCode(after, "typescript"));
      let timeout: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([ready, new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error("Explicit Shiki override did not finish")), 10_000); })]);
      } finally {
        if (timeout) clearTimeout(timeout);
      }
      assert.notDeepEqual(override(), first, "Explicit DIFF_THEME was ignored");
      assert.deepEqual(override().map(stripTerminalSequences), after.split("\n"));
      console.error("Existing diff theme changes, large/unknown-language fallbacks and explicit Shiki override passed (offline)");
    } catch (error) {
      console.error(error);
      failed = true;
    } finally {
      restoreCache?.();
      if (savedOverride === undefined) delete process.env.DIFF_THEME;
      else process.env.DIFF_THEME = savedOverride;
      if (failed) process.exit(1);
      ctx.shutdown();
    }
  });
}
