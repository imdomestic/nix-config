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
      const event = (systemPrompt = identity + suffix): any => ({
        systemPrompt,
        systemPromptOptions: {
          selectedTools: ["read", "bash", "edit", "write", "Agent"],
          sections: { rules: "Keep all custom rules.", custom: "Keep extra sections." },
          contextFiles: [{ path: "/tmp/project/AGENTS.md", content: `Keep project text: ${identity}` }],
          skills: [{ name: "fixture", filePath: "/tmp/skill/SKILL.md", description: "Keep skills." }],
          appendSystemPrompt: "Appended custom guidance.",
          cwd: "/tmp/project",
        },
      });
      const target = (id: string, provider = "agy") => ({ model: { id, provider } });

      for (const provider of ["agy", "agy-completions"]) for (const id of models) {
        const input = event();
        const snapshot = JSON.parse(JSON.stringify(input));
        assert.equal(run(input, target(id, provider)), undefined, "Use structured customPrompt, not a forced full prompt");
        assert.equal(input.systemPromptOptions.customPrompt, "you are a coding assistant");
        assert.equal(input.systemPromptOptions.forceSystemPrompt, undefined);
        assert.deepEqual(input, { ...snapshot, systemPromptOptions: { ...snapshot.systemPromptOptions, customPrompt: "you are a coding assistant" } }, "Only customPrompt may change; context, tools and custom sections stay intact");
        const changed = JSON.stringify(input);
        run(input, target(id, provider));
        assert.equal(JSON.stringify(input), changed, "Repeated hooks must be idempotent");
      }
      for (const [provider, id] of [
        ["cliproxy", "gpt-6.1-sol"], ["cliproxy", "rewind/gpt-6-astra"], ["cliproxy", "rewind2/gpt-6-astra"],
        ["cliproxy", "gemini-4-hydrogen-high"], ["cliproxy", "gemini-3.8-flash-high"],
        ["cliproxy", "other/gemini-4-hydrogen-high"], ["agy", "gemini-unlisted"],
        ["google", models[0]], ["ninfer", "qwen3.8-27b"],
      ]) {
        const input = event(), snapshot = JSON.stringify(input);
        run(input, target(id, provider));
        assert.equal(JSON.stringify(input), snapshot, `${provider}/${id} must stay unchanged`);
      }
      const noModel = event(), noModelSnapshot = JSON.stringify(noModel);
      run(noModel, {});
      assert.equal(JSON.stringify(noModel), noModelSnapshot);
      for (const custom of ["User-defined persona", `User-defined persona\n\n${identity}`, `${identity} extra custom persona`]) {
        const input = event(custom), snapshot = JSON.stringify(input);
        run(input, target(models[0]));
        assert.equal(JSON.stringify(input), snapshot, "Do not overwrite another extension's prompt");
      }
      for (const field of ["customPrompt", "forceSystemPrompt"]) for (const custom of ["", identity, "Custom persona"]) {
        const input = event();
        input.systemPromptOptions[field] = custom;
        const snapshot = JSON.stringify(input);
        run(input, target(models[0]));
        assert.equal(JSON.stringify(input), snapshot, "Respect explicit custom/forced prompts, even matching Pi's identity");
      }
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
        assert.deepEqual(otherHeaders, { "X-Keep": "untouched" });
      }
      const disabled: Record<string, any> = {};
      installAntigravityPrompt({ on(name: string, handler: any) { disabled[name] = handler; } } as any);
      const input = event(), snapshot = JSON.stringify(input);
      disabled.before_agent_start(input, target(models[0]));
      assert.equal(JSON.stringify(input), snapshot, "No configured models means no prompt changes");
      console.error(`Gemini compact prompt: ${models.length} models in two providers; exact phrase, retained structured context/tools, explicit prompts and session headers passed`);
    } catch (error) {
      console.error(error);
      process.exitCode = 1;
    }
    ctx.shutdown();
  });
}
