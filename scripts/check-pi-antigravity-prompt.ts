// Run inside an offline Pi process with scripts/check-pi-antigravity-prompt.sh.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import installAntigravityPrompt from "../home/hank/modules/pi/antigravity-prompt.ts";

export default function (pi: ExtensionAPI): void {
  pi.on("session_start", (_event, ctx) => {
    try {
      const models: string[] = JSON.parse(readFileSync(process.env.PI_TEST_ANTIGRAVITY_MODELS!, "utf8"));
      assert(models.includes("gemini-3.8-flash-high"));
      for (const level of ["low", "medium", "high", "xhigh"]) assert(models.includes(`gemini-4-hydrogen-${level}`));
      const handlers: Record<string, any> = {};
      installAntigravityPrompt({ on(name: string, handler: any) { handlers[name] = handler; } } as any, models);
      assert.deepEqual(Object.keys(handlers), ["before_agent_start", "before_provider_headers"]);
      const run = handlers.before_agent_start;
      const identity = "You are a coding assistant running inside pi, a coding agent harness. Help users inspect files, run commands, and modify code.";
      const suffix = `\n\n<tools>read, bash, edit, write, Agent</tools>\n<rules>Keep all tool rules.</rules>\n<project_context>AGENTS.md: ${identity}</project_context>\n<skills>Keep skills.</skills>\n<cwd>/tmp/project</cwd>\nAppended custom guidance.`;
      const prompt = identity + suffix;
      const event = (systemPrompt = prompt) => ({ systemPrompt, systemPromptOptions: { sections: { rules: "Keep all tool rules." } } });
      const target = (id: string, provider = "agy") => ({ model: { id, provider } });

      for (const provider of ["agy", "agy-completions"]) for (const id of models) {
        const input = event();
        const snapshot = JSON.stringify(input);
        const result = run(input, target(id, provider));
        assert(result.systemPrompt.startsWith("You are Antigravity Agent, a powerful agentic AI coding assistant designed by the Google engineering team.\nYou are pair programming with a USER"));
        assert.equal(result.systemPrompt.slice(result.systemPrompt.indexOf("\n\n")), suffix, "Only the opening identity may change");
        assert.equal(JSON.stringify(input), snapshot, "Do not mutate base prompt options or context");
        assert.equal(run(event(result.systemPrompt), target(id, provider)), undefined, "Never duplicate the agy opening");
      }
      for (const [provider, id] of [
        ["cliproxy", "gpt-6.1-sol"], ["cliproxy", "rewind/gpt-6-astra"], ["cliproxy", "rewind2/gpt-6-astra"],
        ["cliproxy", "gemini-4-hydrogen-high"], ["cliproxy", "gemini-3.8-flash-high"],
        ["cliproxy", "vertex/gemini-4-hydrogen-high"], ["agy", "gemini-unlisted"],
        ["google", models[0]], ["ninfer", "qwen3.8-27b"],
      ]) assert.equal(run(event(), target(id, provider)), undefined, `${provider}/${id} must stay unchanged`);
      assert.equal(run(event(), {}), undefined, "No selected model must stay unchanged");
      const headers = { "X-Keep": "untouched" };
      const sessionContext = { ...target(models[0]), sessionManager: { getSessionId: () => "native-session-one" } };
      handlers.before_provider_headers({ headers }, sessionContext);
      assert.deepEqual(headers, { "X-Keep": "untouched", "X-Agy-Session-Id": "native-session-one" });
      const chatHeaders = {};
      handlers.before_provider_headers({ headers: chatHeaders }, { ...sessionContext, ...target(models[0], "agy-completions") });
      assert.deepEqual(chatHeaders, { "X-Agy-Session-Id": "native-session-one" });
      for (const provider of ["cliproxy", "google", "ninfer"]) {
        const otherHeaders = { "X-Keep": "untouched" };
        handlers.before_provider_headers({ headers: otherHeaders }, { ...sessionContext, ...target(models[0], provider) });
        assert.deepEqual(otherHeaders, { "X-Keep": "untouched" }, "Session affinity is scoped to agy only");
      }
      for (const custom of ["User-defined persona", `User-defined persona\n\n${prompt}`, `${identity} extra custom persona\n\n${suffix}`]) {
        assert.equal(run(event(custom), target(models[0])), undefined, "Respect explicit custom prompts and only match the opening");
      }
      assert(run(event(identity), target(models[0])).systemPrompt.startsWith("You are Antigravity Agent"));
      assert(run(event(), target(models[0])));
      assert.equal(run(event(), target("gpt-6.1-sol")), undefined, "Switching away must not leave model-specific state");
      assert(run(event(), target(models[0])), "Switching back must apply again");
      const disabled: Record<string, any> = {};
      installAntigravityPrompt({ on(name: string, handler: any) { disabled[name] = handler; } } as any);
      assert.equal(disabled.before_agent_start(event(), target(models[0])), undefined, "No configured models means no rewrites");
      console.error(`Antigravity prompt: ${models.length} scoped models, exact prefix, preserved context, custom prompts, idempotence and model switches passed`);
    } catch (error) {
      console.error(error);
      process.exitCode = 1;
    }
    ctx.shutdown();
  });
}
