import { execFile } from "node:child_process";
import { homedir } from "node:os";
import { promisify } from "node:util";
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

const gitMarkers = [
  ["conflicted", "=", "error"],
  ["staged", "+", "success"],
  ["modified", "!", "warning"],
  ["renamed", "»", "warning"],
  ["deleted", "✘", "error"],
  ["untracked", "?", "muted"],
  ["stashed", "$", "dim"],
  ["ahead", "↑", "success"],
  ["behind", "↓", "warning"],
] as const;

type GitStatus = { branch?: string } & Record<typeof gitMarkers[number][0], number>;

export function parseGitStatus(output: string): GitStatus {
  const status: GitStatus = { conflicted: 0, staged: 0, modified: 0, renamed: 0, deleted: 0, untracked: 0, stashed: 0, ahead: 0, behind: 0 };
  // NUL-delimited porcelain keeps whitespace/control characters in filenames out of the parser.
  const records = output.split("\0");
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (record.startsWith("# branch.head ")) {
      const head = record.slice(14);
      status.branch = head === "(detached)" ? "HEAD" : head;
    } else if (record.startsWith("# branch.ab ")) {
      const counts = /^# branch\.ab \+(\d+) -(\d+)$/.exec(record);
      if (counts) [status.ahead, status.behind] = counts.slice(1).map(Number);
    } else if (record.startsWith("# stash ")) {
      status.stashed = Number(record.slice(8)) || 0;
    } else if (record.startsWith("? ")) {
      status.untracked++;
    } else if (record.startsWith("u ")) {
      status.conflicted++;
    } else if (record.startsWith("1 ") || record.startsWith("2 ")) {
      const [index, worktree] = record.slice(2, 4);
      if (index !== ".") status.staged++;
      if (worktree === "M" || worktree === "T") status.modified++;
      if (index === "R" || worktree === "R") status.renamed++;
      if (index === "D" || worktree === "D") status.deleted++;
      if (record.startsWith("2 ")) i++; // Rename/copy records have a second, original-path field.
    }
  }
  return status;
}

const execFileAsync = promisify(execFile);
export async function readGitStatus(cwd: string, signal?: AbortSignal): Promise<GitStatus | undefined> {
  try {
    const { stdout } = await execFileAsync("git", ["--no-optional-locks", "status", "--porcelain=v2", "--branch", "--show-stash", "-z"], {
      cwd, signal, timeout: 2_000, maxBuffer: 1024 * 1024, encoding: "utf8",
    });
    return parseGitStatus(stdout);
  } catch {
    return undefined;
  }
}

type StatuslineOptions = { showTokenRate?: boolean; now?: () => number; readGitStatus?: typeof readGitStatus };

export default function (pi: ExtensionAPI, options: StatuslineOptions = {}) {
  const { showTokenRate = false, now = () => performance.now(), readGitStatus: readGit = readGitStatus } = options;
  let requestStartedAt: number | undefined;
  let tokensPerSecond: number | undefined;
  let refresh: (() => void) | undefined;
  let refreshGit: (() => void) | undefined;
  let stopGit: (() => void) | undefined;

  pi.on("before_agent_start", (_event, ctx) => {
    if (ctx.mode === "tui") refreshGit?.();
  });
  const mutatingTools = new Set(["edit", "write", "bash", "powershell"]);
  pi.on("tool_execution_end", (event, ctx) => {
    if (ctx.mode === "tui" && mutatingTools.has(event.toolName)) refreshGit?.();
  });
  pi.on("session_shutdown", () => {
    stopGit?.();
    requestStartedAt = undefined;
    tokensPerSecond = undefined;
    refresh = undefined;
  });

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
  }
  pi.on("session_start", (_event, ctx) => {
    resetRate();
    if (ctx.mode !== "tui") return;

    ctx.ui.setFooter((tui, theme, footerData) => {
      stopGit?.();
      const requestRender = () => tui.requestRender();
      refresh = requestRender;
      const controller = new AbortController();
      let git: GitStatus | undefined;
      let disposed = false;
      let dirty = false;
      let pending: Promise<void> | undefined;
      const updateGit = () => {
        dirty = true;
        if (pending) return;
        pending = (async () => {
          // Coalesce tool bursts; if another refresh arrives, discard the older snapshot.
          while (dirty && !disposed) {
            dirty = false;
            const next = await readGit(ctx.cwd, controller.signal).catch(() => undefined);
            if (disposed) return;
            if (dirty) continue;
            git = next;
            requestRender();
          }
        })().finally(() => {
          pending = undefined;
          if (dirty && !disposed) updateGit();
        });
      };
      refreshGit = updateGit;
      const unsubscribe = footerData.onBranchChange(() => {
        git = undefined;
        updateGit();
        requestRender();
      });
      // No idle polling; external changes are picked up at the next task. See docs/decisions.md#pi-git-status.
      const cleanupGit = () => {
        if (disposed) return;
        disposed = true;
        controller.abort();
        unsubscribe();
        if (refreshGit === updateGit) refreshGit = undefined;
        if (stopGit === cleanupGit) stopGit = undefined;
      };
      stopGit = cleanupGit;
      updateGit();
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

      // Register before FleetView so the statusline sits directly below the editor.
      ctx.ui.setWidget("statusline", () => ({
        dispose() {
          cleanupGit();
          if (refresh === requestRender) refresh = undefined;
        },
        invalidate() {},
        render(width: number): string[] {
          const groups = [theme.fg("mdLink", shortCwd(ctx.cwd))];
          const branch = footerData.getGitBranch() ?? git?.branch;
          if (branch) {
            const snapshot = git?.branch === branch ? git : undefined;
            const markers = snapshot
              ? gitMarkers.filter(([key]) => snapshot[key] > 0).map(([key, symbol, color]) => theme.fg(color, `${symbol}${snapshot[key]}`))
              : [];
            const status = markers.length ? ` ${theme.fg("dim", "[")}${markers.join(" ")}${theme.fg("dim", "]")}` : "";
            groups.push(theme.fg("success", `\ue0a0 ${clean(branch)}`) + status);
          }

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
      }), { placement: "belowEditor" });
      // Keep the footer data provider, but render its content in the widget above FleetView.
      return {
        render: () => [],
        invalidate() {},
        dispose() { ctx.ui.setWidget("statusline", undefined); },
      };
    });
  });
}
