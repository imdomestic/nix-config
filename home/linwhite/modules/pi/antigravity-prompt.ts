import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const piIdentity = "You are a coding assistant running inside pi, a coding agent harness. Help users inspect files, run commands, and modify code.";
// Native agy identity/task text; investigation: docs/incidents.md#pi-antigravity-prompt-429.
const antigravityIdentity = [
  "You are Antigravity Agent, a powerful agentic AI coding assistant designed by the Google engineering team.",
  "You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.",
].join("\n");

export default function installAntigravityPrompt(pi: ExtensionAPI, modelIds: readonly string[] = []): void {
  const models = new Set(modelIds);
  pi.on("before_agent_start", (event, ctx) => {
    if (ctx.model?.provider !== "cliproxy" || !models.has(ctx.model.id)) return;
    // Only replace Pi's exact default opening, never a custom prompt or project text.
    if (event.systemPrompt !== piIdentity && !event.systemPrompt.startsWith(`${piIdentity}\n\n`)) return;
    return { systemPrompt: antigravityIdentity + event.systemPrompt.slice(piIdentity.length) };
  });
}
