// Run as an offline Pi extension; see docs/decisions.md#pi-better-render.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { join } from "node:path";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import { AssistantMessageComponent, createAgentSession, DefaultResourceLoader, SessionManager, SettingsManager, ToolExecutionComponent, UserMessageComponent, getAgentDir, getMarkdownTheme, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Container, stripTerminalSequences, visibleWidth } from "@earendil-works/pi-tui";
import installSubagents from "../home/hank/modules/pi/subagents.ts";

const until = async (check: () => boolean, label: string) => {
  const deadline = performance.now() + 10_000;
  while (!check()) {
    assert(performance.now() < deadline, `Timed out: ${label}`);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
};

export default function (pi: ExtensionAPI) {
  pi.registerProvider("pi-render-test", {
    api: "openai-completions", apiKey: "offline-test", baseUrl: "http://127.0.0.1:1",
    models: [{ id: "probe", name: "Offline render probe", reasoning: false, input: ["text"], contextWindow: 128_000, maxTokens: 100, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }],
    streamSimple(model: any, _transcript: any, options: any) {
      const stream = createAssistantMessageEventStream();
      const message: any = {
        role: "assistant", api: model.api, provider: model.provider, model: model.id, timestamp: Date.now(), content: [], stopReason: "pending",
        usage: { input: 1, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 1, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      };
      stream.push({ type: "start", partial: message });
      const abort = () => {
        message.stopReason = "aborted";
        message.errorMessage = "Offline probe stopped";
        stream.push({ type: "error", reason: "aborted", error: message });
        stream.end();
      };
      if (options?.signal?.aborted) abort();
      else options?.signal?.addEventListener("abort", abort, { once: true });
      return stream;
    },
  } as any);
  pi.on("session_start", async (_event, host) => {
    try {
      const better = process.env.PI_RENDER_PACKAGE;
      const cc = process.env.PI_CC_RENDER_PACKAGE;
      const subagents = process.env.PI_SUBAGENTS_PACKAGE;
      assert(better && cc && subagents, "Set PI_RENDER_PACKAGE, PI_CC_RENDER_PACKAGE and PI_SUBAGENTS_PACKAGE to the Nix package paths");
      process.env.PI_BETTER_RENDER_IMAGES = "placeholder";
      process.env.PI_BETTER_RENDER_MERMAID_INSTALL = "0";
      process.env.PI_BETTER_RENDER_FONT_DOWNLOAD = "0";
      process.env.PI_BETTER_RENDER_TEX = "off";

      const { default: installPi } = await import(join(getAgentDir(), "extensions/hank-pi.ts"));
      const { RichMarkdown } = await import(`${better}/src/render/rich-markdown.ts`);
      const { loadMathJaxSync, rasterize } = await import(`${better}/src/math/mathjax.ts`);
      const { imageMode, installFrameHook, registerImage, placeholderRows, forgetImages } = await import(`${better}/src/math/kitty.ts`);
      const { loadMermaid } = await import(`${better}/src/render/mermaid.ts`);
      const { config, updateConfig } = await import(`${cc}/extensions/config/config.ts`);
      updateConfig({ mode: "on" });

      const { renderWorkflowCard } = await import(`${subagents}/src/ui/workflow-card.ts`);
      const workflowCard = renderWorkflowCard({
        progress: [{ type: "workflow_agent", index: 0, label: "fixture-agent", state: "start" }],
        task: { status: "running", workflowName: "fixture-workflow", startTime: Date.now() },
        agentCount: 2, agentCap: 1,
      }, host.ui.theme);
      let adaptedWorkflow: any;
      installSubagents({ ...pi, on: () => () => {}, registerTool: (tool: any) => { adaptedWorkflow = tool; } } as any,
        api => api.registerTool({ name: "SubagentWorkflow", label: "fixture", description: "fixture", parameters: {} as any,
          execute: async () => ({ content: [], details: {} }), renderResult: () => workflowCard }));
      for (const width of [100, 42, 10, 100]) {
        const full = workflowCard.render(width);
        assert(full.map(stripTerminalSequences).some(line => line.includes("╰─")), "The fixture must contain a real workflow tree");
        const result = { content: [], details: { taskId: "fixture" } };
        const collapsed = adaptedWorkflow.renderResult(result, { expanded: false }, host.ui.theme, { isError: false }).render(width);
        assert.deepEqual(collapsed, full.filter((line: string, index: number) => index === 0 || /^\s*(?:⚠|!)/.test(stripTerminalSequences(line))));
        assert(collapsed.map(stripTerminalSequences).some((line: string) => line.includes("⚠")), "Collapsing must retain budget warnings");
        assert.deepEqual(adaptedWorkflow.renderResult(result, { expanded: true }, host.ui.theme, { isError: false }).render(width), full);
        assert.deepEqual(adaptedWorkflow.renderResult(result, { expanded: false }, host.ui.theme, { isError: true }).render(width), full, "Do not truncate errors");
        assert.deepEqual(adaptedWorkflow.renderResult({ content: [], details: {} }, { expanded: false }, host.ui.theme, { isError: false }).render(width), full, "Do not truncate non-workflow fallback output");
      }
      console.error("Workflow cards: collapsed summary, expanded tree, budget warnings, errors and widths passed");

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
        const tools = new Map<string, any>();
        const flags = new Map<string, any>();
        const bus = new EventEmitter();
        const notifications: string[] = [];
        const tui: any = new Container();
        Object.assign(tui, { mode: "fullscreen", terminal: { write() {}, columns: 100, rows: 30 }, requestRender() {}, handleInput() {}, handleViewportInput() {} });
        const widgets = new Map<string, { component: any; placement: string }>();
        const statuses = new Map<string, string>();
        let footer: any;
        let editorFactory: any;
        let footerMounts = 0;
        let editorMounts = 0;
        const ui: any = {
          ...host.ui,
          theme: host.ui.theme,
          setWidget(key: string, factory: any, options: any) {
            assert(key !== "agents" || factory === undefined, "The upper Agents tree must remain disabled");
            widgets.get(key)?.component.dispose?.();
            widgets.delete(key);
            if (typeof factory === "function") widgets.set(key, { component: factory(tui, host.ui.theme), placement: options?.placement ?? "aboveEditor" });
          },
          setStatus(key: string, text: string | undefined) { text === undefined ? statuses.delete(key) : statuses.set(key, text); },
          getToolsExpanded: () => false,
          notify(text: string, level: string) { if (level === "error") notifications.push(text); },
          onTerminalInput: () => () => {}, addAutocompleteProvider() {}, getEditorText: () => "",
          setFooter(factory: any) {
            footerMounts++;
            footer?.dispose?.();
            footer = factory?.(tui, host.ui.theme, { onBranchChange: () => () => {}, getGitBranch: () => "main", getExtensionStatuses: () => statuses });
          },
          setEditorComponent(factory: any) { editorMounts++; editorFactory = factory; },
        };
        const ctx: any = { ...host, mode: "tui", hasUI: true, ui, cwd: "/tmp", getContextUsage: () => undefined, sessionManager: SessionManager.inMemory("/tmp"), isIdle: () => true, isProjectTrusted: () => false };
        const api: any = {
          ...pi,
          on(event: string, handler: any) {
            const list = handlers.get(event) ?? [];
            list.push(handler);
            handlers.set(event, list);
            return () => {};
          },
          registerCommand(name: string, command: any) { commands.set(name, command); },
          registerTool(definition: any) { tools.set(definition.name, definition); },
          getAllTools: () => [...tools.values()], getActiveTools: () => [...tools.keys()], setActiveTools() {}, appendEntry() {}, sendMessage() {},
          registerShortcut() {}, getThinkingLevel: () => "off",
          registerMessageRenderer() {}, registerEntryRenderer() {},
          registerFlag(name: string, flag: any) { flags.set(name, flag); }, getFlag: (name: string) => flags.get(name)?.default,
          events: { on(name: string, handler: any) { bus.on(name, handler); return () => bus.off(name, handler); }, emit: (name: string, data: any) => bus.emit(name, data) },
        };
        const emit = async (event: string, payload: any = {}) => {
          for (const handler of [...(handlers.get(event) ?? [])]) await handler(payload, ctx);
        };

        installPi(api);
        assert(commands.has("agents"));
        assert(tools.has("SubagentWorkflow"));
        const agentTool = tools.get("Agent");
        assert(agentTool.description.includes("after direct investigation"), "Agent must prefer direct investigation before delegation");
        assert(!agentTool.description.includes("used proactively"), "Agent must not encourage automatic delegation");
        assert(!agentTool.promptGuidelines.some((rule: string) => rule.startsWith("For broad codebase")), "Broad searches must not automatically trigger agents");
        assert(tools.get("SubagentWorkflow").promptGuidelines.every((rule: string) => rule.includes("explicitly requests")), "Workflow guidance must require explicit opt-in");
        const { loadSettings } = await import(`${subagents}/src/settings.ts`);
        assert.equal(loadSettings().widgetMode, "all", "Exercise a project override that tries to restore the upper tree");
        assert(![...commands.keys()].some(name => name.startsWith("ctx-")), "Magic Context commands must not be loaded");
        assert(![...tools.keys()].some(name => name.startsWith("ctx_")), "Magic Context tools must not be loaded");
        await emit("session_start");
        await new Promise((resolve) => setTimeout(resolve, 20));
        assert.equal(footerMounts, 1, "Only the local statusline may own the footer");
        assert.equal(editorMounts, 1, "Only the local prompt may own the editor");
        assert.equal(typeof editorFactory, "function");
        assert.deepEqual(footer.render(100), []);
        assert(widgets.has("statusline"));
        const managerKey = Symbol.for("pi-subagents:manager");
        const manager = (globalThis as any)[managerKey];
        assert(manager);
        const started = await tools.get("Agent").execute("render-background", {
          subagent_type: "general-purpose", model: "pi-render-test/probe", prompt: "Wait for offline cancellation", description: "Bootstrap FleetView probe", run_in_background: true,
        }, new AbortController().signal, () => {}, ctx);
        const record = manager.getRecord(started.details.agentId);
        await until(() => record?.session?.isStreaming && widgets.has("fleet"), "real background child and FleetView");
        assert.equal((globalThis as any)[managerKey], manager, "The combined child bootstrap must not replace the parent manager");
        assert.deepEqual([...widgets].filter(([, widget]) => widget.placement === "belowEditor").map(([key]) => key), ["statusline", "fleet"]);
        await emit("tool_execution_start", { toolName: "read", toolCallId: "tree-guard-probe" });
        assert(!widgets.has("agents"));
        assert(!statuses.has("subagents"), "The redundant running-agent status must stay hidden with the upper tree");
        const fleetLines = widgets.get("fleet")!.component.render(100).map(stripTerminalSequences);
        assert.equal(fleetLines[1], "  ● main");
        assert(fleetLines[2].startsWith("  ○ Agent"));
        assert(fleetLines.every((line: string) => line.trim()), "FleetView must not add blank rows");
        await record.session.abort();
        await manager.waitForAll();
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
        for (const name of ["Agent", "SubagentWorkflow", "get_subagent_result", "steer_subagent"]) {
          const definition = tools.get(name);
          const component: any = new ToolExecutionComponent(name, `check-${name}`, {}, { showImages: false }, definition, tui);
          if (definition.renderCall) assert.equal(component.getCallRenderer(), definition.renderCall, `${name} lost its native call renderer`);
          if (definition.renderResult) assert.equal(component.getResultRenderer(), definition.renderResult, `${name} lost its native result renderer`);
        }
        assert(tools.get("SubagentWorkflow").renderCall({ name: "test" }, host.ui.theme).render(80).some((line: string) => stripTerminalSequences(line).includes("SubagentWorkflow")));
        const liveAssistant = AssistantMessageComponent.prototype.updateContent;
        const liveUser = UserMessageComponent.prototype.render;
        const { runInChildSessionContext } = await import(`${subagents}/src/child-context.js`);
        const childLoader = new DefaultResourceLoader({
          cwd: "/tmp", agentDir: getAgentDir(), noExtensions: true,
          noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
          additionalExtensionPaths: [join(getAgentDir(), "extensions/hank-pi.ts")],
        });
        await runInChildSessionContext(() => childLoader.reload());
        assert.deepEqual(childLoader.getExtensions().errors, []);
        const { session: child } = await runInChildSessionContext(() => createAgentSession({
          cwd: "/tmp", agentDir: getAgentDir(), modelRuntime: (host.modelRegistry as any).runtime,
          sessionManager: SessionManager.inMemory("/tmp"), settingsManager: SettingsManager.inMemory({}), resourceLoader: childLoader,
        }));
        try {
          await child.bindExtensions({ onError: (error) => { throw error; } });
          assert.equal(AssistantMessageComponent.prototype.updateContent, liveAssistant, "A child factory replaced the parent's assistant renderer");
          await child.extensionRunner?.emit({ type: "session_shutdown", reason: "quit" });
          assert.equal(AssistantMessageComponent.prototype.updateContent, liveAssistant, "A child shutdown removed the parent's rich Markdown patch");
          assert.equal(UserMessageComponent.prototype.render, liveUser, "A child changed the parent's user-message patch");
          assert.equal(ToolExecutionComponent.prototype.render, toolRender, "A child changed the parent's CC tool renderer");
        } finally {
          child.dispose();
        }
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
        footer.dispose();
        assert.equal(widgets.size, 0, "All bootstrap widgets must be removed on shutdown");
        assert.equal(AssistantMessageComponent.prototype.updateContent, originalAssistant, "Assistant patch leaked across reload");
        assert.equal(UserMessageComponent.prototype.render, originalUser, "User prefix patch leaked across reload");
        assert.equal(ToolExecutionComponent.prototype.getCallRenderer, originalToolCall, "CC call renderer leaked across reload");
        assert.equal(ToolExecutionComponent.prototype.getResultRenderer, originalToolResult, "CC result renderer leaked across reload");
        assert.equal((globalThis as any)[Symbol.for("pi-subagents:manager")], undefined, "Subagent manager leaked across reload");
        ctx.mode = "rpc";
        await emit("session_start");
        assert.equal(UserMessageComponent.prototype.render, originalUser, "RPC mode installed a terminal-only prefix");
        assert.equal(editorMounts, 1, "RPC must not mount the editor");
        assert.equal(footerMounts, 1, "RPC must not mount the footer");
        await emit("session_shutdown");
        console.error(`generation ${generation + 1}: actual bootstrap, single editor/footer, FleetView-only real child, CC tools, inline math, Markdown, resize, toggle and cleanup passed`);
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
