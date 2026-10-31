// Run as an offline Pi extension; see docs/decisions.md#pi-better-render.
import assert from "node:assert/strict";
import { AssistantMessageComponent, ToolExecutionComponent, UserMessageComponent, getMarkdownTheme, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Container, stripTerminalSequences, visibleWidth } from "@earendil-works/pi-tui";
import { installRenderers } from "../home/hank/modules/pi/render.ts";

export default function (pi: ExtensionAPI) {
  pi.on("session_start", async (_event, host) => {
    try {
      const better = process.env.PI_RENDER_PACKAGE;
      const cc = process.env.PI_CC_RENDER_PACKAGE;
      assert(better && cc, "Set PI_RENDER_PACKAGE and PI_CC_RENDER_PACKAGE to the Nix package paths");
      process.env.PI_BETTER_RENDER_IMAGES = "placeholder";
      process.env.PI_BETTER_RENDER_MERMAID_INSTALL = "0";
      process.env.PI_BETTER_RENDER_FONT_DOWNLOAD = "0";
      process.env.PI_BETTER_RENDER_TEX = "off";

      const { default: betterRender } = await import(`${better}/src/index.ts`);
      const { RichMarkdown } = await import(`${better}/src/render/rich-markdown.ts`);
      const { loadMathJaxSync, rasterize } = await import(`${better}/src/math/mathjax.ts`);
      const { imageMode, installFrameHook, registerImage, placeholderRows, forgetImages } = await import(`${better}/src/math/kitty.ts`);
      const { loadMermaid } = await import(`${better}/src/render/mermaid.ts`);
      const { default: ccStyle, getCompactThinkingConfig } = await import(`${cc}/extensions/renderer/index.ts`);
      const { installCompactThinking } = await import(`${cc}/extensions/feature/compact-thinking.ts`);
      const { config, updateConfig } = await import(`${cc}/extensions/config/config.ts`);
      updateConfig({ mode: "on", enableMarkdownEnhance: false });

      loadMathJaxSync();
      const raster = rasterize({ tex: String.raw`\frac{-b+\sqrt{b^2-4ac}}{2a}`, display: true, color: "#cdd6f4", cellWidth: 10, cellHeight: 20, maxColumns: 80, maxRows: 20 });
      assert.equal(Buffer.from(raster.base64, "base64").subarray(0, 8).toString("hex"), "89504e470d0a1a0a");
      for (const env of [{ TERM_PROGRAM: "rex" }, { TERM: "xterm-rex" }]) {
        assert.equal(imageMode(env, true), "placeholder", "Rex must anchor images to text cells");
        assert.equal(imageMode(env, false), "off", "Rex still requires Kitty graphics support");
        assert.equal(imageMode({ ...env, TMUX: "/tmp/tmux" }, true), "off", "Rex detection must not enable unsupported tmux images");
      }
      const frames: string[] = [];
      const terminal = { write(data: string) { frames.push(data); } };
      const uninstall = installFrameHook(terminal, imageMode({ TERM_PROGRAM: "rex" }, true));
      try {
        const id = 1234567;
        registerImage(id, raster.base64, raster.columns, raster.rows);
        const rows = placeholderRows(id, raster.columns, raster.rows);
        for (let redraw = 0; redraw < 20; redraw++) {
          terminal.write(`\x1b[H\x1b[2K${rows.join("\r\n")}`);
          terminal.write("\x1b[H\x1b[2Kplain text replaces the first formula row");
        }
        const output = frames.join("");
        assert.equal((output.match(/a=T,/g) ?? []).length, 1, "Repeated repaint must not create more image placements");
        assert(output.includes("U=1"), "Formula placements must be virtual");
        assert(!output.includes("a=p,"), "Rex repaint must not emit accumulating direct placements");
        terminal.write(`\x1b[2J\x1b[H${rows.join("\r\n")}`);
        assert.equal((frames.join("").match(/a=T,/g) ?? []).length, 2, "A screen clear must restore the formula image");
      } finally {
        uninstall();
        forgetImages();
      }
      console.error("Rex detection, repeated repaint, text replacement and clear recovery passed");
      assert(await loadMermaid(), "The packaged Mermaid engine must load without npm");

      const originalAssistant = AssistantMessageComponent.prototype.updateContent;
      const originalUser = UserMessageComponent.prototype.render;
      const originalTool = ToolExecutionComponent.prototype.render;
      const originalToolCall = ToolExecutionComponent.prototype.getCallRenderer;
      const originalToolResult = ToolExecutionComponent.prototype.getResultRenderer;
      const message = {
        role: "assistant", api: "openai-responses", provider: "test", model: "test", timestamp: 100,
        content: [
          { type: "thinking", thinking: "Checking the layout." },
          { type: "text", text: "# Render check\n\n行内公式 $x^2+1$。\n\n| 项目 | 结果 |\n| --- | --- |\n| 中文 | OK |\n\n```ts\nconst value = 1;\n```\n\n```mermaid\nflowchart LR\n  A --> B\n```" },
        ],
        stopReason: "stop",
        usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      };
      const saved = JSON.stringify(message);

      for (let generation = 0; generation < 2; generation++) {
        const handlers = new Map<string, Array<(event: any, ctx: any) => any>>();
        const commands = new Map<string, any>();
        const notifications: string[] = [];
        const tui: any = new Container();
        Object.assign(tui, { mode: "fullscreen", terminal: { write() {}, columns: 100, rows: 30 }, requestRender() {}, handleInput() {}, handleViewportInput() {} });
        const ui: any = {
          theme: host.ui.theme,
          setWidget(_key: string, factory: any) { if (typeof factory === "function") factory(tui, host.ui.theme); },
          setStatus() {}, getToolsExpanded: () => false,
          notify(text: string, level: string) { if (level === "error") notifications.push(text); },
          onTerminalInput: () => () => {},
        };
        const ctx: any = { mode: "tui", hasUI: true, ui, cwd: "/tmp", sessionManager: { getBranch: () => [], getEntries: () => [] }, isIdle: () => true };
        const api: any = {
          on(event: string, handler: any) {
            const list = handlers.get(event) ?? [];
            list.push(handler);
            handlers.set(event, list);
            return () => {};
          },
          registerCommand(name: string, command: any) { commands.set(name, command); },
          registerTool() {}, getAllTools: () => [], getActiveTools: () => [], appendEntry() {},
        };
        const emit = async (event: string, payload: any = {}) => {
          for (const handler of [...(handlers.get(event) ?? [])]) await handler(payload, ctx);
        };

        installRenderers(api, (pi) => ccStyle(pi, undefined, installCompactThinking(pi, getCompactThinkingConfig())), betterRender);
        await emit("session_start");
        await new Promise((resolve) => setTimeout(resolve, 20));
        const toolRender = ToolExecutionComponent.prototype.render;
        assert.notEqual(toolRender, originalTool, "CC must retain its tool renderer");

        const checkUserMessages = () => {
          for (const text of ["这是一条中文消息，带 emoji 🙂。\n第二行继续。", "# 标题\n\n- 第一项\n- 第二项\n\n```ts\nconst value = 1;\n```", "\n\n**加粗**和 `inline code`。", ""]) {
            for (const padding of [0, 1]) {
              const component: any = new UserMessageComponent(text, getMarkdownTheme(), padding);
              for (const width of [100, 42, 10, 42, 100]) {
                const native = originalUser.call(component, width - 2).map(stripTerminalSequences);
                const lines = component.render(width);
                const plain = lines.map(stripTerminalSequences);
                const first = native.findIndex((line) => line.trim().length > 0);
                assert.deepEqual(plain.map((line: string) => line.slice(2)), native, "The prompt gutter changed Markdown content");
                assert.equal(plain.filter((line: string) => line.startsWith("❯ ")).length, first < 0 ? 0 : 1, "Messages must have exactly one prompt prefix");
                if (first >= 0) assert(plain[first].startsWith("❯ "), "Prefix must be on the first content line");
                if (lines.length > 0) {
                  assert(lines[0].startsWith("\x1b]133;A\x07"), "Prompt-zone start marker moved");
                  assert(lines[lines.length - 1].startsWith("\x1b]133;B\x07\x1b]133;C\x07"), "Prompt-zone end markers moved");
                }
                assert(lines.every((line: string) => visibleWidth(line) <= width), `User message exceeded ${width} columns`);
                assert.equal(component.text, text, "Rendering changed the stored user text");
              }
            }
          }
          const narrow = new UserMessageComponent("ok", getMarkdownTheme(), 0);
          for (const width of [1, 2]) {
            assert.deepEqual(narrow.render(width).map(stripTerminalSequences), originalUser.call(narrow, width).map(stripTerminalSequences));
          }
        };
        checkUserMessages();
        tui.mode = "regular";
        checkUserMessages();
        tui.mode = "fullscreen";

        for (const hidden of [false, true]) {
          const component: any = new AssistantMessageComponent(message as any, hidden, getMarkdownTheme(), "Thinking...", 0);
          tui.addChild(component);
          for (const width of [100, 42, 100]) {
            component.updateContent(message, true);
            component.render(width);
            component.updateContent(message, false);
            const lines = component.render(width);
            assert(component.contentContainer.children.some((child: any) => child instanceof RichMarkdown), "CC thinking visibility must not bypass rich Markdown");
            assert(lines.some((line: string) => line.includes("\u{10eeee}")), "Inline math must use image placeholders");
            assert(lines.every((line: string) => visibleWidth(line) <= width), `Rendered output exceeded ${width} columns`);
          }
        }
        const tool: any = new ToolExecutionComponent("bash", "test-call", { command: "printf test" }, { showImages: false });
        assert(tool.render(100).some((line: string) => line.includes("printf test")), "CC bash card disappeared");
        await commands.get("better-render").handler("off", ctx);
        const plain: any = new AssistantMessageComponent(message as any, true, getMarkdownTheme(), "Thinking...", 0);
        assert(!plain.contentContainer.children.some((child: any) => child instanceof RichMarkdown));
        await commands.get("better-render").handler("on", ctx);
        plain.updateContent(message, false);
        assert(plain.contentContainer.children.some((child: any) => child instanceof RichMarkdown));
        assert.equal(ToolExecutionComponent.prototype.render, toolRender, "Toggling better-render changed CC tools");
        await commands.get("ccstyle").handler("compact", ctx);
        await new Promise((resolve) => setTimeout(resolve, 20));
        checkUserMessages();
        plain.updateContent(message, false);
        assert(plain.contentContainer.children.some((child: any) => child instanceof RichMarkdown), "CC compact mode bypassed rich replies");
        await commands.get("ccstyle").handler("off", ctx);
        await new Promise((resolve) => setTimeout(resolve, 20));
        checkUserMessages();
        await commands.get("ccstyle").handler("on", ctx);
        await new Promise((resolve) => setTimeout(resolve, 20));
        checkUserMessages();
        assert.equal(JSON.stringify(message), saved, "Rendering changed the stored message");
        assert.deepEqual(notifications, []);
        await emit("session_shutdown");
        assert.equal(AssistantMessageComponent.prototype.updateContent, originalAssistant, "Assistant patch leaked across reload");
        assert.equal(UserMessageComponent.prototype.render, originalUser, "User prefix patch leaked across reload");
        assert.equal(ToolExecutionComponent.prototype.getCallRenderer, originalToolCall, "CC call renderer leaked across reload");
        assert.equal(ToolExecutionComponent.prototype.getResultRenderer, originalToolResult, "CC result renderer leaked across reload");
        ctx.mode = "rpc";
        await emit("session_start");
        assert.equal(UserMessageComponent.prototype.render, originalUser, "RPC mode installed a terminal-only prefix");
        await emit("session_shutdown");
        console.error(`generation ${generation + 1}: user prompt prefix, CC tools, thinking visibility, inline math, Markdown, resize, toggle and cleanup passed`);
      }
      assert.equal(config.enableMarkdownEnhance, false);
      console.error("Pi renderer checks passed (offline; no model request or home activation)");
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
    host.shutdown();
  });
}
