import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import install from "../home/linwhite/modules/pi/antigravity-prompt.ts";

export default function (pi: ExtensionAPI): void {
  pi.on("session_start", (_event, ctx) => {
    try {
      const ids: string[] = JSON.parse(readFileSync(process.env.PI_TEST_AGY_MODELS!, "utf8"));
      assert(ids.includes("gemini-3.8-flash-high") && ids.includes("gemini-4-hydrogen-high"));
      const handlers: Record<string, any> = {};
      install({ on(name: string, handler: any) { handlers[name] = handler; } } as any, ["gemini-3.8-flash-high"], ids);
      const identity = "You are a coding assistant running inside pi, a coding agent harness. Help users inspect files, run commands, and modify code.";
      const suffix = "\n\n<project_context>Keep project rules.</project_context>";
      const event = (): any => ({ systemPrompt: identity + suffix, systemPromptOptions: { contextFiles: [{ path: "AGENTS.md", content: "Keep rules." }] } });
      const target = (provider: string, id: string) => ({ model: { provider, id } });
      for (const id of ids) {
        const e = event(), before = structuredClone(e);
        assert.equal(handlers.before_agent_start(e, target("agy", id)), undefined);
        assert.deepEqual(e, { ...before, systemPromptOptions: { ...before.systemPromptOptions, customPrompt: "you are a coding assistant" } });
        const headers = { "X-Keep": "yes" };
        handlers.before_provider_headers({ headers }, { ...target("agy", id), sessionManager: { getSessionId: () => "session-id" } });
        assert.deepEqual(headers, { "X-Keep": "yes", "X-Agy-Session-Id": "session-id" });
      }
      for (const field of ["customPrompt", "forceSystemPrompt"]) for (const value of ["", identity, "custom"]) {
        const e = event();
        e.systemPromptOptions[field] = value;
        const before = structuredClone(e);
        handlers.before_agent_start(e, target("agy", ids[0]));
        assert.deepEqual(e, before, "Explicit prompts must win");
      }
      for (const [provider, id] of [["agy", "unlisted"], ["agy-completions", ids[0]], ["cliproxy", "gpt-6.1-sol"], ["google", ids[0]]]) {
        const e = event(), before = structuredClone(e);
        assert.equal(handlers.before_agent_start(e, target(provider, id)), undefined);
        assert.deepEqual(e, before);
        const headers = { "X-Keep": "yes" };
        handlers.before_provider_headers({ headers }, target(provider, id));
        assert.deepEqual(headers, { "X-Keep": "yes" });
      }
      const legacy = event();
      const result = handlers.before_agent_start(legacy, target("cliproxy", "gemini-3.8-flash-high"));
      assert(result.systemPrompt.startsWith("You are Antigravity Agent,"));
      assert(result.systemPrompt.endsWith(suffix), "Existing CLIProxy prompt must remain unchanged");
      assert.equal(legacy.systemPromptOptions.customPrompt, undefined);
      const noModel = event();
      assert.equal(handlers.before_agent_start(noModel, {}), undefined);
      console.error(`linwhite agy: ${ids.length} models, prompt scope, overrides, session header and legacy CLIProxy passed`);
    } catch (error) {
      console.error(error);
      process.exitCode = 1;
    }
    ctx.shutdown();
  });
}
