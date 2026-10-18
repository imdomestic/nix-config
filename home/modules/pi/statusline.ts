import { homedir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { truncateToWidth } from "@earendil-works/pi-tui";

// Match Claude Code's statusline; data differences: docs/decisions.md#pi-claude-statusline.
const paint = (code: number, text: string) => `\x1b[${code}m${text}\x1b[0m`;
const clean = (text: string) => text.replace(/[\x00-\x1f\x7f]/g, " ");
const separator = ` ${paint(2, "|")} `;

function shortCwd(cwd: string): string {
  const home = homedir();
  const path = cwd === home ? "~" : cwd.startsWith(`${home}/`) ? `~${cwd.slice(home.length)}` : cwd;
  const parts = path.split("/");
  return clean(parts.length <= 4 ? path : `…/${parts.slice(-3).join("/")}`);
}

export default function (pi: ExtensionAPI) {
  pi.on("session_start", (_event, ctx) => {
    if (ctx.mode !== "tui") return;

    ctx.ui.setFooter((tui, _theme, footerData) => {
      const unsubscribe = footerData.onBranchChange(() => tui.requestRender());
      let costKey = "";
      let cost = 0;

      function sessionCost(): number {
        const manager = ctx.sessionManager;
        const key = `${manager.getSessionId()}:${manager.getEntryCount()}:${manager.getLeafId()}`;
        if (key === costKey) return cost;
        costKey = key;
        cost = 0;

        // Count all recorded spend, including compacted turns and tool-owned model calls.
        for (const entry of manager.getEntries()) {
          const usage = entry.type === "message"
            ? entry.message.role === "assistant" || entry.message.role === "toolResult"
              ? entry.message.usage
              : undefined
            : "usage" in entry ? entry.usage : undefined;
          const amount = usage?.cost?.total;
          if (typeof amount === "number" && Number.isFinite(amount) && amount >= 0) cost += amount;
        }
        return cost;
      }

      return {
        dispose: unsubscribe,
        invalidate() {},
        render(width: number): string[] {
          const groups = [paint(34, shortCwd(ctx.cwd))];
          const branch = footerData.getGitBranch();
          if (branch) groups.push(paint(32, `\ue0a0 ${clean(branch)}`));

          let model = paint(36, clean(ctx.model?.id ?? "no-model"));
          if (ctx.model?.reasoning) model += ` ${paint(2, pi.getThinkingLevel())}`;
          groups.push(model, `${paint(2, "$")}${sessionCost().toFixed(2)}`);

          const lines = [truncateToWidth(groups.join(separator), width)];
          const statuses = [...footerData.getExtensionStatuses().entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([, text]) => text.replace(/[\r\n\t]/g, " ").replace(/ +/g, " ").trim());
          if (statuses.length) lines.push(truncateToWidth(statuses.join(" "), width));
          return lines;
        },
      };
    });
  });
}
