import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CustomEditor, getSelectListTheme, initTheme, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { CURSOR_MARKER, foregroundAnsi, getTerminalColorMode, parseColor, stripTerminalSequences, visibleWidth } from "@earendil-works/pi-tui";
import installPrompt from "../home/hank/modules/pi/prompt-prefix.ts";
import installStatusline from "../home/hank/modules/pi/statusline.ts";

export default function (pi: ExtensionAPI) {
  pi.on("session_start", async (_event, host) => {
    try {
      const agent = process.env.PI_CODING_AGENT_DIR;
      assert(agent);
      const names = Object.keys(JSON.parse(readFileSync(join(agent, "themes.json"), "utf8")));
      let renders = 0;
      const tui: any = { mode: "fullscreen", terminal: { rows: 30, columns: 100 }, requestRender() { renders++; } };
      const keybindings: any = { matches: (data: string, action: string) => data === "\x1b" && action === "app.interrupt" };
      const gray = foregroundAnsi(parseColor("#c5c5c5"), getTerminalColorMode());
      const handlers: Record<string, any> = {};
      let editorFactory: any;
      let footerFactory: any;
      const api: any = {
        on(event: string, handler: any) { handlers[event] = handler; },
        getThinkingLevel: () => "xhigh",
      };
      const model: any = { id: "model-test", reasoning: true, contextWindow: 128_000 };
      let usage: any = { tokens: 38_400, contextWindow: 128_000, percent: 30 };
      let entriesReads = 0;
      const entries: any[] = [
        { type: "message", message: { role: "assistant", usage: { cost: { total: 1.25 } } } },
        { type: "message", message: { role: "toolResult", usage: { cost: { total: 2 } } } },
        { type: "custom", usage: { cost: { total: 0.75 } } },
        { type: "message", message: { role: "user", usage: { cost: { total: 99 } } } },
        { type: "custom", usage: { cost: { total: -1 } } },
      ];
      const ctx: any = {
        mode: "rpc", cwd: "/tmp/project", model,
        getContextUsage: () => usage,
        sessionManager: {
          getSessionId: () => "ui-test", getEntryCount: () => entries.length, getLeafId: () => "leaf",
          getEntries() { entriesReads++; return entries; },
        },
        ui: {
          theme: host.ui.theme,
          setEditorComponent(factory: any) { editorFactory = factory; },
          setFooter(factory: any) { footerFactory = factory; },
        },
      };
      installPrompt(api);
      const startPrompt = handlers.session_start;
      installStatusline(api);
      const startStatusline = handlers.session_start;
      await startPrompt({}, ctx);
      await startStatusline({}, ctx);
      assert.equal(editorFactory, undefined, "RPC must not install a terminal editor");
      assert.equal(footerFactory, undefined, "RPC must not install a terminal footer");
      ctx.mode = "tui";
      await startPrompt({}, ctx);
      await startStatusline({}, ctx);
      assert.equal(typeof editorFactory, "function");
      assert.equal(typeof footerFactory, "function");
      initTheme("evergarden-winter");
      const editorTheme = { borderColor: (text: string) => host.ui.theme.fg("border", text), selectList: getSelectListTheme() };
      const editor = editorFactory(tui, editorTheme, keybindings);
      const native = new CustomEditor(tui, editorTheme, keybindings, { paddingX: 2, embedWorkingStatus: true });
      editor.focused = native.focused = true;
      editor.setWorkingStatusIndicator({
        renderInBorder: () => editor.borderColor("Working..."),
        renderSpinnerInBorder: () => editor.borderColor("·"),
      });
      native.setWorkingStatusIndicator({
        renderInBorder: () => native.borderColor("Working..."),
        renderSpinnerInBorder: () => native.borderColor("·"),
      } as any);
      let branchChanged!: () => void;
      let disposed = 0;
      const footerData: any = {
        onBranchChange(callback: () => void) { branchChanged = callback; return () => { disposed++; }; },
        getGitBranch: () => "main",
        getExtensionStatuses: () => new Map([["z", "second\nstatus"], ["a", "first\tstatus"]]),
      };
      const footer = footerFactory(tui, host.ui.theme, footerData);
      let previousFooter: string | undefined;
      let previousPalette: string | undefined;

      for (const name of names) {
        initTheme(name);
        for (const mode of ["fullscreen", "regular"]) {
          tui.mode = mode;
          for (const level of ["off", "xhigh", "max", "bash"]) {
            const color = level === "bash" ? host.ui.theme.getBashModeBorderColor() : host.ui.theme.getThinkingBorderColor(level as any);
            for (const padding of [0, 2, 4]) {
              editor.setPaddingX(padding);
              native.setPaddingX(Math.max(2, padding));
              for (const text of ["", "中文🙂\nsecond line", "word ".repeat(50)]) {
                editor.setText(text);
                native.setText(text);
                for (const width of [1, 2, 5, 12, 42, 100]) {
                  const actualPadding = Math.min(editor.getPaddingX(), Math.max(0, Math.floor((width - 1) / 2)));
                  // Native Editor needs room for its cursor and double-width graphemes.
                  if (width === 1 && text.length > 0) continue;
                  if (text.includes("中文") && width - 2 * actualPadding - (actualPadding ? 0 : 1) < 2) continue;
                  editor.borderColor = color;
                  native.borderColor = color;
                  const lines = editor.render(width);
                  const plain = lines.map(stripTerminalSequences);
                  const expected = native.render(width).map(stripTerminalSequences);
                  if (actualPadding >= 2 && expected[1] !== undefined) {
                    expected[1] = " ".repeat(actualPadding - 2) + "❯ " + expected[1].slice(actualPadding);
                  }
                  assert.deepEqual(plain, expected, `${name}: editor geometry or contents changed`);
                  assert(lines.every((line: string) => visibleWidth(line) <= width), `${name}/${level}: editor exceeded ${width} columns (padding ${padding}, text ${JSON.stringify(text)}, widths ${lines.map(visibleWidth)})`);
                  const foregrounds = lines.join("").match(/\x1b\[(?:38;[^m]+|3[0-7]|9[0-7])m/g) ?? [];
                  assert(foregrounds.length > 0);
                  assert(foregrounds.every((sequence: string) => sequence === gray), `${name}/${level}: editor is not fixed gray-white`);
                  assert(!/\x1b\[(?:48;[^m]+|4[0-7]|10[0-7])m/.test(lines.join("")), "Editor background must remain terminal default");
                  assert.equal(lines.join("").split(CURSOR_MARKER).length - 1, 1, "IME cursor marker moved or disappeared");
                  assert.equal(editor.getText(), native.getText());
                  assert.deepEqual(editor.getCursor(), native.getCursor());
                }
              }
            }
          }
        }

        usage = { tokens: 38_400, contextWindow: 128_000, percent: 30 };
        const lines = footer.render(300);
        const output = stripTerminalSequences(lines[0]);
        assert(output.includes("model-test xhigh | ctx 38.4k/128k (30%) | $4.00"), output);
        assert.equal(stripTerminalSequences(lines[1]), "first status second status");
        assert(lines[0].includes(host.ui.theme.fg("accent", "model-test")));
        assert(lines[0].includes(host.ui.theme.fg("mdLink", "/tmp/project")));
        assert(lines[0].includes(host.ui.theme.fg("dim", "|")));
        assert(lines[0].includes(host.ui.theme.fg("text", "4.00")));
        assert(lines[1].includes(host.ui.theme.fg("muted", "first status")));
        const palette = ["accent", "mdLink", "text", "dim", "success", "muted"].map((token) => host.ui.theme.getFgAnsi(token as any)).join("");
        if (previousFooter && palette !== previousPalette) assert.notEqual(lines[0], previousFooter, "Footer retained the previous theme's ANSI colors");
        previousFooter = lines[0];
        previousPalette = palette;
        for (const percent of [0, 75, 95, 110]) {
          usage = { tokens: percent / 100 * 128_000, contextWindow: 128_000, percent };
          const colored = footer.render(300)[0];
          const color = percent >= 90 ? "error" : percent >= 70 ? "warning" : "success";
          assert(colored.includes(host.ui.theme.fg(color, `(${percent}%)`)));
        }
        usage = { tokens: null, contextWindow: 128_000, percent: null };
        assert(stripTerminalSequences(footer.render(300)[0]).includes("ctx ?/128k | $4.00"));
        usage = { tokens: 1_024_000, contextWindow: 1_280_000, percent: null };
        assert(stripTerminalSequences(footer.render(300)[0]).includes("ctx 1.02M/1.28M (80%)"));
        for (const width of [1, 12, 42, 100]) assert(footer.render(width).every((line: string) => visibleWidth(line) <= width));
        console.error(`${name}: fixed gray-white editor, cursor/geometry, themed footer and context states passed (${host.ui.theme.getColorMode()})`);
      }
      assert.equal(entriesReads, 1, "Context/theme changes must not rescan session cost every frame");
      const beforeRender = renders;
      branchChanged();
      assert.equal(renders, beforeRender + 1);
      footer.dispose();
      assert.equal(disposed, 1);
      let submitted = "";
      editor.onSubmit = (text: string) => { submitted = text; };
      editor.setText("message");
      editor.render(80);
      editor.handleInput("\r");
      assert.equal(submitted, "message", "Rendering must not insert ANSI or the prompt prefix into submissions");
      let escaped = false;
      editor.onEscape = () => { escaped = true; };
      editor.handleInput("\x1b");
      assert(escaped, "CustomEditor app keybindings must remain wired");
      console.error("Pi editor/statusline checks passed (offline; no home activation)");
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
    host.shutdown();
  });
}
