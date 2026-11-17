import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { stripTerminalSequences, type Component } from "@earendil-works/pi-tui";

function compactWorkflowCard(component: Component): Component {
  return {
    render(width) {
      const lines = component.render(width);
      // Keep the live header and budget warnings; expansion retains the full tree.
      return lines.filter((line, index) => index === 0 || /^\s*(?:⚠|!)/.test(stripTerminalSequences(line)));
    },
    invalidate() { component.invalidate(); },
  };
}

const agentPolicy = "Use Agent only when the user explicitly requests delegation, or after direct investigation establishes a substantial, self-contained task that clearly benefits from parallel work or context isolation. Default to doing the work in the main session; matching an agent type alone is not a reason to delegate.";
const workflowPolicy = "Use SubagentWorkflow only when the user explicitly requests a workflow or multi-agent orchestration. Complexity, multiple stages, review, or independent verification alone are not permission to launch a workflow.";

const agentDescription = `Delegate a substantial, self-contained task to an autonomous agent.

${agentPolicy}

Do not delegate routine file searches, reading a few files, small edits, ordinary debugging, or a review the main session can do itself. Try read/bash first; do not launch agents merely because a task is broad, a specialized type exists, or extra reviewers might be useful. Keep reasoning, decisions, and final verification in the main session. Never duplicate a delegated investigation.

Available agent types are listed in the subagent_type parameter. Custom agents load from the project .pi/agents/ or global agent directory. Give each agent a self-contained brief, say whether it may modify files, and limit it to a non-overlapping task.

Agents run in the background by default. Use run_in_background: false only when the very next action depends on the result and no other useful work is possible. Completion notifications arrive automatically: never poll, sleep waiting, or guess results. Use get_subagent_result to retrieve a completed result and steer_subagent to redirect a running agent. Resume keeps a finished agent's context; a new spawn does not.

Check actual diffs and run tests before claiming delegated changes work. Parallel writers need non-overlapping file ownership or explicit worktree isolation; a worktree cannot see uncommitted changes. Do not spawn extra review agents or nested agents by default.`;

export default function installSubagents(pi: ExtensionAPI, extension: (pi: ExtensionAPI) => void): void {
  // Keep the upper tree off even if a project setting overrides widgetMode.
  // Policy and UI boundaries: docs/decisions.md#pi-subagents-main-first.
  const guardedUIs = new WeakMap<ExtensionContext["ui"], ExtensionContext["ui"]>();
  const guardContext = <T extends ExtensionContext>(ctx: T): T => {
    let ui = guardedUIs.get(ctx.ui);
    if (!ui) {
      ui = new Proxy(ctx.ui, {
        get(target, key) {
          if (key === "setWidget") return (name: string, content: any, options: any) =>
            target.setWidget(name, name === "agents" ? undefined : content, options);
          if (key === "setStatus") return (name: string, text: string | undefined) =>
            target.setStatus(name, name === "subagents" ? undefined : text);
          return Reflect.get(target, key, target);
        },
      });
      guardedUIs.set(ctx.ui, ui);
      guardedUIs.set(ui, ui);
    }
    return { ...ctx, ui };
  };

  pi.on("session_start", (_event, ctx) => {
    ctx.ui.setWidget("agents", undefined);
    ctx.ui.setStatus("subagents", undefined);
  });

  extension({
    ...pi,
    on(event, handler) {
      return pi.on(event, (event, ctx) => handler(event, guardContext(ctx)));
    },
    registerCommand(name, command) {
      pi.registerCommand(name, {
        ...command,
        handler: (args, ctx) => command.handler(args, guardContext(ctx)),
      });
    },
    registerTool(definition) {
      const agent = definition.name === "Agent";
      const workflow = definition.name === "SubagentWorkflow";
      pi.registerTool({
        ...definition,
        ...(agent ? {
          description: agentDescription,
          promptSnippet: "Delegate substantial independent work sparingly; prefer direct tools",
          promptGuidelines: [
            agentPolicy,
            "Use read/bash directly for routine searches, a few file reads, small edits, and ordinary debugging. Do not automatically spawn review or nested agents.",
            "When Agent runs in the background, wait for its completion notification without polling or sleeping. Never invent results.",
            "Verify Agent's actual changes with diffs and tests; do not treat its summary as proof.",
          ],
        } : {}),
        ...(workflow ? {
          promptGuidelines: [workflowPolicy],
          renderResult: definition.renderResult ? (result, options, theme, context) => {
            const component = definition.renderResult!(result, options, theme, context);
            if (options.expanded || context.isError || !(result.details as any)?.taskId) return component;
            return compactWorkflowCard(component);
          } : undefined,
        } : {}),
        execute: (id, params, signal, onUpdate, ctx) =>
          definition.execute(id, params, signal, onUpdate, guardContext(ctx)),
      });
    },
  } as ExtensionAPI);
}
