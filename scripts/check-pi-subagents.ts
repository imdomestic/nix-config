// Real Pi SDK sessions with a deterministic provider; no external model requests.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createAssistantMessageEventStream, getCurrentTools } from "@earendil-works/pi-ai";
import { createAgentSession, DefaultResourceLoader, getAgentDir, SessionManager, SettingsManager, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { stripTerminalSequences, visibleWidth } from "@earendil-works/pi-tui";
import installStatusline from "../home/hank/modules/pi/statusline.ts";

const pause = () => new Promise<void>((resolve) => setTimeout(resolve, 10));
async function until(check: () => boolean, label: string) {
  const deadline = performance.now() + 10_000;
  while (!check()) {
    assert(performance.now() < deadline, `Timed out: ${label}`);
    await pause();
  }
}

async function checkFleetFooter(pkg: string, theme: any): Promise<void> {
  const { FleetList } = await import(join(pkg, "src/ui/fleet-list.ts"));
  const widgets = new Map<string, any>();
  const handlers: Record<string, any> = {};
  const tui: any = { mode: "fullscreen", requestRender() {} };
  let footer: any;
  let listening = false;
  const ctx: any = {
    mode: "tui", cwd: "/tmp/project", getContextUsage: () => undefined,
    sessionManager: { getSessionId: () => "fleet-test", getEntryCount: () => 0, getLeafId: () => null, getEntries: () => [] },
    ui: {
      setWidget(key: string, create: any, options: any) {
        widgets.get(key)?.dispose?.();
        widgets.delete(key);
        if (create) {
          assert.equal(options?.placement, "belowEditor");
          widgets.set(key, create(tui, theme));
        }
      },
      setFooter(create: any) {
        footer = create(tui, theme, {
          onBranchChange: () => () => {}, getGitBranch: () => "main", getExtensionStatuses: () => new Map(),
        });
      },
      onTerminalInput() { listening = true; return () => { listening = false; }; },
      getEditorText: () => "",
    },
  };
  installStatusline({ on(event: string, handler: any) { handlers[event] = handler; }, getThinkingLevel: () => "off" } as any, {
    readGitStatus: async () => undefined,
  });
  handlers.session_start({}, ctx);
  const record = { id: "probe", type: "Plan", description: "中文🙂 layout probe", session: undefined as any, status: "running", startedAt: Date.now() };
  let records = [record];
  const fleet = new FleetList({ listAgents: () => records }, new Map());
  const render = (width = 200) => [...widgets.values()].flatMap(widget => widget.render(width));
  const plain = () => render().map(stripTerminalSequences);
  const originalSetInterval = globalThis.setInterval;
  const originalClearInterval = globalThis.clearInterval;
  let tick: (() => void) | undefined;
  globalThis.setInterval = ((callback: () => void) => { tick = callback; return 1; }) as any;
  globalThis.clearInterval = (() => { tick = undefined; }) as any;
  try {
    fleet.setUICtx(ctx.ui);
    fleet.ensureTimer();
    fleet.update();
    assert.deepEqual([...widgets.keys()], ["statusline"], "A child without a session must not become an unopenable fleet row");
    assert(tick, "FleetView must keep refreshing while an asynchronous child session starts");
    record.session = {};
    tick();
    assert.deepEqual([...widgets.keys()], ["statusline", "fleet"], "Mount order must be statusline then FleetView");
    assert.deepEqual(footer.render(200), [], "The native footer must not duplicate statusline content");
    assert(plain()[0].startsWith("/tmp/project |"));
    assert(plain()[1].startsWith("  esc to interrupt"));
    assert.equal(plain()[2], "  ● main");
    assert(plain()[3].startsWith("  ○ Agent  中文🙂 layout probe"), JSON.stringify(plain()));
    assert.equal(plain().length, 4, "No blank rows between statusline, hints, main and subagents");
    for (const mode of ["fullscreen", "regular"]) {
      tui.mode = mode;
      for (const width of [1, 12, 42, 100, 200]) {
        assert(render(width).every(line => visibleWidth(line) <= width), `${mode}: layout exceeded ${width} columns`);
        assert(render(width).every(line => stripTerminalSequences(line).trim()), `${mode}: blank fleet row at width ${width}`);
      }
    }
    assert.deepEqual(fleet.handleKey("\x1b[B"), { consume: true });
    assert(plain()[1].startsWith("  ↑↓ select"));
    assert.deepEqual(fleet.handleKey("\x1b[B"), { consume: true });
    assert.equal(plain()[2], "  ○ main");
    assert(plain()[3].startsWith("  ● Agent"), "Selection must keep the two-space indent");
    assert.deepEqual(fleet.handleKey("\x1b"), { consume: true });
    assert.equal(plain()[2], "  ● main");
    fleet.setWorkflowSource(() => [{ id: "workflow-probe", name: "layout-workflow", status: "running", doneCount: 0, totalCount: 1, startedAt: Date.now(), tokens: 0 }], () => {});
    assert(plain()[3].startsWith("  ○ workflow  layout-workflow"));
    assert(plain()[4].startsWith("  ○ Agent"));
    fleet.setEnabled(false);
    assert.deepEqual([...widgets.keys()], ["statusline"]);
    fleet.setEnabled(true);
    assert.deepEqual([...widgets.keys()], ["statusline", "fleet"]);
    records = [];
    fleet.setWorkflowSource(() => [], () => {});
    fleet.update();
    assert.equal(plain().length, 1, "An idle session must keep only the statusline");
    assert(!tick, "An idle session must not keep polling");
    records = [{ ...record, session: undefined }];
    fleet.update();
    assert(tick, "A pending child must restart polling even without an existing timer");
    fleet.setEnabled(false);
    assert(!tick, "Disabling FleetView must stop polling even during child startup");
    fleet.setEnabled(true);
    assert(tick, "Re-enabling FleetView must resume watching the pending child");
    records[0].status = "error";
    tick();
    assert(!tick, "A child that fails before session creation must not leave a timer behind");
    assert.equal(plain().length, 1);
    assert(listening);
  } finally {
    fleet.dispose();
    handlers.session_shutdown({}, ctx);
    footer.dispose();
    globalThis.setInterval = originalSetInterval;
    globalThis.clearInterval = originalClearInterval;
  }
  assert(!tick, "Disposal must stop the fleet refresh timer");
  assert(!listening, "Disposal must release the fleet input listener");
  assert.equal(widgets.size, 0, "Disposal must remove both widgets");
  console.error("Fleet footer: async child startup, statusline-first, no spacers, preserved indent/navigation, workflows, widths, re-enable and cleanup passed");
}

export default function (pi: ExtensionAPI) {
  const requests: Array<{ tools: string[]; task: string }> = [];
  pi.registerProvider("subagents-test", {
    api: "openai-completions", apiKey: "offline-test", baseUrl: "http://127.0.0.1:1",
    models: [{ id: "rewind/probe", name: "Offline probe", reasoning: false, input: ["text"], contextWindow: 128_000, maxTokens: 1000, cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 } }],
    streamSimple(model: any, transcript: any, options: any) {
      const stream = createAssistantMessageEventStream();
      void (async () => {
        const user = [...transcript.messages].reverse().find((m: any) => m.role === "user");
        const task = typeof user?.content === "string" ? user.content : user?.content?.map((b: any) => b.text ?? "").join("") ?? "";
        const tools = getCurrentTools(transcript.messages).map((t: any) => t.name);
        requests.push({ tools, task });
        const message: any = {
          role: "assistant", api: model.api, provider: model.provider, model: model.id, timestamp: Date.now(), content: [], stopReason: "pending",
          usage: { input: 10, output: 5, cacheRead: 0, cacheWrite: 0, totalTokens: 15, cost: { input: 0.05, output: 0.075, cacheRead: 0, cacheWrite: 0, total: 0.125 } },
        };
        stream.push({ type: "start", partial: message });
        if (task.includes("[wait-for-abort]")) {
          if (!options?.signal?.aborted) await new Promise<void>((resolve) => options?.signal?.addEventListener("abort", () => resolve(), { once: true }));
          message.stopReason = "aborted";
          message.errorMessage = "Offline cancellation";
          stream.push({ type: "error", reason: "aborted", error: message });
        } else if (task.includes("[read-fixture]") && !transcript.messages.some((m: any) => m.role === "toolResult" && m.toolName === "read")) {
          const call = { type: "toolCall", id: `read-${requests.length}`, name: "read", arguments: { path: "fixture.txt" } };
          message.content.push(call);
          stream.push({ type: "toolcall_start", contentIndex: 0, partial: message });
          stream.push({ type: "toolcall_end", contentIndex: 0, toolCall: call, partial: message });
          message.stopReason = "toolUse";
          stream.push({ type: "done", reason: "toolUse", message });
        } else {
          const text = "OFFLINE_SUBAGENT_OK";
          message.content.push({ type: "text", text });
          stream.push({ type: "text_start", contentIndex: 0, partial: message });
          stream.push({ type: "text_delta", contentIndex: 0, delta: text, partial: message });
          stream.push({ type: "text_end", contentIndex: 0, content: text, partial: message });
          message.stopReason = "stop";
          stream.push({ type: "done", reason: "stop", message });
        }
        stream.end();
      })().catch((error) => { console.error(error); process.exit(1); });
      return stream;
    },
  } as any);

  pi.on("session_start", async (_event, host) => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (() => { throw new Error("Subagent checks must not access the network"); }) as any;
    try {
      const agentDir = getAgentDir();
      const cwd = process.env.PI_SUBAGENTS_WORKSPACE;
      const pkg = process.env.PI_SUBAGENTS_PACKAGE;
      assert(cwd && pkg);
      assert.equal(JSON.parse(readFileSync(join(pkg, "package.json"), "utf8")).version, "0.22.1");
      for (const peer of ["@earendil-works/pi-coding-agent", "@earendil-works/pi-ai", "@earendil-works/pi-tui", "typebox"]) {
        assert(!existsSync(join(pkg, "node_modules", peer)), "The package must use Pi's host SDK, not bundle another copy");
      }
      await checkFleetFooter(pkg, host.ui.theme);
      const { default: subagents } = await import(join(agentDir, "extensions/tintin-subagents.ts"));
      const model = host.modelRegistry.find("subagents-test", "rewind/probe");
      assert(model);
      const managerKey = Symbol.for("pi-subagents:manager");

      for (let generation = 0; generation < 2; generation++) {
        const tools = new Map<string, any>();
        const commands = new Set<string>();
        const notifications: any[] = [];
        const events: Array<{ type: string; payload: any }> = [];
        let ctx: any;
        const loader = new DefaultResourceLoader({
          cwd, agentDir, noExtensions: true, noSkills: true, noThemes: true, noPromptTemplates: true, noContextFiles: true,
          extensionFactories: [(api) => {
            for (const type of ["subagents:started", "subagents:completed", "subagents:failed", "subagents:settings_loaded", "subagents:disposed"]) {
              api.events.on(type, payload => events.push({ type, payload }));
            }
            subagents({
              ...api,
              registerTool(definition: any) { tools.set(definition.name, definition); api.registerTool(definition); },
              registerCommand(name: string, command: any) { commands.add(name); api.registerCommand(name, command); },
              // Exercise native completion delivery without spending a parent-model turn.
              sendMessage(message: any) { notifications.push(message); },
            } as ExtensionAPI);
            api.on("session_start", (_e, context) => { ctx = context; });
          }],
        });
        await loader.reload();
        assert.deepEqual(loader.getExtensions().errors, []);
        const { session } = await createAgentSession({
          cwd, agentDir, model, modelRuntime: (host.modelRegistry as any).runtime,
          sessionManager: SessionManager.create(cwd, join(agentDir, "sessions")),
          settingsManager: SettingsManager.inMemory({ compaction: { enabled: false } }), resourceLoader: loader,
        });
        const errors: any[] = [];
        const call = (name: string, params: any) => tools.get(name).execute(`check-${generation}-${name}`, params, new AbortController().signal, () => {}, ctx);
        try {
          await session.bindExtensions({ onError: error => errors.push(error) });
          assert(ctx);
          assert.deepEqual([...tools.keys()].sort(), ["Agent", "SubagentWorkflow", "get_subagent_result", "steer_subagent"].sort());
          assert(commands.has("agents"));
          assert(!("schedule" in tools.get("Agent").parameters.properties));
          const loadedSettings = events.find(e => e.type === "subagents:settings_loaded")?.payload.settings;
          assert.equal(loadedSettings?.maxConcurrent, 100);
          assert.equal(loadedSettings?.maxConcurrentForeground, 100);
          assert.equal(loadedSettings?.reportUsage, true);
          assert.equal(loadedSettings?.fleetView, true);
          assert.equal(loadedSettings?.widgetMode, "off");
          const manager = (globalThis as any)[managerKey];
          assert(manager && !manager.hasRunning());

          const before = requests.length;
          const result = await call("Agent", { subagent_type: "Plan", prompt: "[read-fixture]", description: "Offline foreground", run_in_background: false });
          assert(JSON.stringify(result).includes("OFFLINE_SUBAGENT_OK"));
          assert.equal(result.details.status, "completed");
          assert.equal(result.details.toolUses, 1, "The child must execute a real built-in read");
          assert.equal(result.usage.cost.total, 0.25, "Two child turns must reach parent cost accounting once");
          const child = manager.getRecord(result.details.agentId);
          assert(child.session.sessionFile && existsSync(child.session.sessionFile), "Children must retain resumable sessions");
          assert(child.session.messages.some((m: any) => m.role === "toolResult" && JSON.stringify(m.content).includes("READ_ONLY_FIXTURE")));
          assert(requests.slice(before).every(r => !r.tools.includes("edit") && !r.tools.includes("write") && !r.tools.includes("Agent")));
          assert.equal((globalThis as any)[managerKey], manager, "Child extension loading must not steal the parent manager");

          const resumed = await call("Agent", { subagent_type: "Plan", resume: child.id, prompt: "Continue the read-only probe", description: "Offline resume", run_in_background: false });
          assert.equal(resumed.details.status, "completed");
          assert.equal(resumed.usage.cost.total, 0.125);

          const background = await call("Agent", { subagent_type: "Plan", prompt: "Background probe", description: "Offline background" });
          assert.equal(background.details.status, "background");
          await manager.waitForAll();
          await until(() => notifications.some(n => JSON.stringify(n).includes("Offline background")), "background completion notification");
          const fetched = await call("get_subagent_result", { agent_id: background.details.agentId });
          assert(JSON.stringify(fetched).includes("OFFLINE_SUBAGENT_OK"));
          assert.equal(fetched.usage.cost.total, 0.125);
          const fetchedAgain = await call("get_subagent_result", { agent_id: background.details.agentId });
          assert.equal(fetchedAgain.usage, undefined, "Reading a result twice must not double-charge usage");

          const workflow = await call("SubagentWorkflow", {
            script: 'export const meta = { name: "offline-workflow", description: "Offline workflow" }; return await parallel([() => agent("One", { agentType: "Plan" }), () => agent("Two", { agentType: "Plan" })]);',
          });
          assert(workflow.details.taskId);
          await until(() => notifications.some(n => n.details?.id === workflow.details.taskId), "workflow completion");
          const notice = notifications.find(n => n.details?.id === workflow.details.taskId);
          assert.equal(notice.details.status, "completed", JSON.stringify(notice));
          assert(notice.content.includes("OFFLINE_SUBAGENT_OK"));
          assert(events.some(e => e.type === "subagents:completed"));

          const pending = await call("Agent", { subagent_type: "Plan", prompt: "[wait-for-abort]", description: "Offline cancellation" });
          await until(() => manager.getRecord(pending.details.agentId)?.session?.isStreaming, "cancellable child start");
          assert.deepEqual(errors, []);
          await session.extensionRunner?.emit({ type: "session_shutdown", reason: "quit" });
          assert.equal((globalThis as any)[managerKey], undefined, "Shutdown must release the manager and stop active children");
          assert(events.some(e => e.type === "subagents:disposed"));
          console.error(`generation ${generation + 1}: real SDK read-only child, resume, background completion, usage, workflow worker, cancellation and cleanup passed`);
        } finally {
          if ((globalThis as any)[managerKey]) await session.extensionRunner?.emit({ type: "session_shutdown", reason: "quit" });
          session.dispose();
        }
      }
      assert(!existsSync(join(cwd, ".pi", "subagent-schedules")), "Disabled scheduling must not create state");
      console.error("Pi subagent checks passed (offline; no paid model request or home activation)");
    } catch (error) {
      console.error(error);
      process.exit(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
    host.shutdown();
  });
}
