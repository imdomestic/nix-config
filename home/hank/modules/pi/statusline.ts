import { homedir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { truncateToWidth } from "@earendil-works/pi-tui";

// Claude-style grouping, with Pi's theme and context estimate; docs/decisions.md#pi-input-status-colors.
const clean = (text: string) => text.replace(/[\x00-\x1f\x7f]/g, " ");

function formatTokens(tokens: number): string {
  if (tokens >= 1_000_000) return `${(tokens / 1_000_000).toFixed(2).replace(/\.?0+$/, "")}M`;
  if (tokens >= 1_000) return `${(tokens / 1_000).toFixed(1).replace(/\.0$/, "")}k`;
  return String(Math.round(tokens));
}

function shortCwd(cwd: string): string {
  const home = homedir();
  const path = cwd === home ? "~" : cwd.startsWith(`${home}/`) ? `~${cwd.slice(home.length)}` : cwd;
  const parts = path.split("/");
  return clean(parts.length <= 4 ? path : `…/${parts.slice(-3).join("/")}`);
}

type StatuslineOptions = { showTokenRate?: boolean; now?: () => number };

export default function (pi: ExtensionAPI, options: StatuslineOptions = {}) {
  const { showTokenRate = false, now = () => performance.now() } = options;
  let requestStartedAt: number | undefined;
  let tokensPerSecond: number | undefined;
  let refresh: (() => void) | undefined;

  const resetRate = () => {
    requestStartedAt = undefined;
    tokensPerSecond = undefined;
    refresh?.();
  };
  if (showTokenRate) {
    pi.on("turn_start", (_event, ctx) => {
      if (ctx.mode !== "tui") return;
      requestStartedAt = now();
      tokensPerSecond = undefined;
      refresh?.();
    });
    pi.on("message_end", (event, ctx) => {
      if (ctx.mode !== "tui" || event.message.role !== "assistant" || requestStartedAt === undefined) return;
      const elapsedMs = now() - requestStartedAt;
      const output = event.message.usage?.output;
      const failed = event.message.stopReason === "error" || event.message.stopReason === "aborted";
      // Provider output only; freeze before tool execution and never divide by idle time.
      const rate = !failed && typeof output === "number" && Number.isFinite(output) && output > 0 && elapsedMs > 0
        ? output / (elapsedMs / 1_000) : undefined;
      tokensPerSecond = typeof rate === "number" && Number.isFinite(rate) ? rate : undefined;
      requestStartedAt = undefined;
      refresh?.();
    });
    pi.on("agent_end", () => {
      requestStartedAt = undefined;
      refresh?.();
    });
    pi.on("model_select", resetRate);
    pi.on("session_shutdown", () => {
      requestStartedAt = undefined;
      tokensPerSecond = undefined;
      refresh = undefined;
    });
  }
  pi.on("session_start", (_event, ctx) => {
    resetRate();
    if (ctx.mode !== "tui") return;

    ctx.ui.setFooter((tui, theme, footerData) => {
      const requestRender = () => tui.requestRender();
      refresh = requestRender;
      const unsubscribe = footerData.onBranchChange(requestRender);
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
        dispose() {
          unsubscribe();
          if (refresh === requestRender) refresh = undefined;
        },
        invalidate() {},
        render(width: number): string[] {
          const groups = [theme.fg("mdLink", shortCwd(ctx.cwd))];
          const branch = footerData.getGitBranch();
          if (branch) groups.push(theme.fg("success", `\ue0a0 ${clean(branch)}`));

          let model = theme.fg("accent", clean(ctx.model?.id ?? "no-model"));
          if (ctx.model?.reasoning) model += ` ${theme.fg("dim", pi.getThinkingLevel())}`;

          const usage = ctx.getContextUsage();
          const limit = usage?.contextWindow ?? ctx.model?.contextWindow;
          const tokens = usage?.tokens;
          const knownTokens = typeof tokens === "number" && Number.isFinite(tokens) && tokens >= 0;
          const knownLimit = typeof limit === "number" && Number.isFinite(limit) && limit > 0;
          const counts = `${knownTokens ? formatTokens(tokens) : "?"}${knownLimit ? `/${formatTokens(limit)}` : ""}`;
          let context = `${theme.fg("dim", "ctx")} ${theme.fg("text", counts)}`;
          // Compaction makes tokens unknown until the next response; never display that as zero.
          if (knownTokens && knownLimit) {
            const percent = typeof usage?.percent === "number" && Number.isFinite(usage.percent) && usage.percent >= 0
              ? usage.percent : tokens / limit * 100;
            const color = percent >= 90 ? "error" : percent >= 70 ? "warning" : "success";
            context += ` ${theme.fg(color, `(${percent.toFixed(1).replace(/\.0$/, "")}%)`)}`;
          }
          groups.push(model, context, `${theme.fg("dim", "$")}${theme.fg("text", sessionCost().toFixed(2))}`);
          if (showTokenRate && requestStartedAt !== undefined) {
            groups.push(theme.fg("dim", "avg … tok/s"));
          } else if (showTokenRate && tokensPerSecond !== undefined) {
            const rate = tokensPerSecond.toFixed(1).replace(/\.0$/, "");
            groups.push(`${theme.fg("dim", "avg")} ${theme.fg("text", rate)} ${theme.fg("dim", "tok/s")}`);
          }

          const separator = ` ${theme.fg("dim", "|")} `;
          const lines = [truncateToWidth(groups.join(separator), width)];
          const statuses = [...footerData.getExtensionStatuses().entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([, text]) => text.replace(/[\r\n\t]/g, " ").replace(/ +/g, " ").trim());
          if (statuses.length) lines.push(truncateToWidth(statuses.map((text) => theme.fg("muted", text)).join(" "), width));
          return lines;
        },
      };
    });
  });
}
