import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const piIdentity = "You are a coding assistant running inside pi, a coding agent harness. Help users inspect files, run commands, and modify code.";
// Same native customPrompt path as --system-prompt; docs/incidents.md#pi-cliproxy-flash-compact-prompt.
const compactPrompt = "you are a coding assistant";

export default function installAntigravityPrompt(pi: ExtensionAPI, modelIds: readonly string[] = []): void {
  const models = new Set(modelIds);
  const providers = new Set(["agy", "agy-completions"]);
  pi.on("before_agent_start", (event, ctx) => {
    if (!ctx.model || !providers.has(ctx.model.provider) || !models.has(ctx.model.id)) return;
    const options = event.systemPromptOptions;
    if (options.customPrompt !== undefined || options.forceSystemPrompt !== undefined) return;
    if (event.systemPrompt !== piIdentity && !event.systemPrompt.startsWith(`${piIdentity}\n\n`)) return;
    // Let Pi retain project context, skills, appended sections and real tool declarations.
    options.customPrompt = compactPrompt;
  });
  pi.on("before_provider_headers", (event, ctx) => {
    if (!ctx.model || !providers.has(ctx.model.provider) || !models.has(ctx.model.id)) return;
    event.headers["X-Agy-Session-Id"] = ctx.sessionManager.getSessionId();
  });
}
