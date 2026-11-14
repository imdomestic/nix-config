import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CustomEditor, getSelectListTheme, initTheme, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { CURSOR_MARKER, foregroundAnsi, getTerminalColorMode, parseColor, stripTerminalSequences, visibleWidth } from "@earendil-works/pi-tui";
import installPrompt from "../home/hank/modules/pi/prompt-prefix.ts";
import installStatusline, { parseGitStatus, readGitStatus } from "../home/hank/modules/pi/statusline.ts";
import { createBalanceReader, formatBalance, parseBalanceResponse, type BalanceSnapshot } from "../home/hank/modules/pi/balance.ts";

const settleGit = () => new Promise<void>((resolve) => setImmediate(resolve));

function mountStatusline(factory: any, ctx: any, tui: any, theme: any, footerData: any): any {
  let widget: any;
  ctx.ui.setWidget = (key: string, create: any, options: any) => {
    assert.equal(key, "statusline");
    widget?.dispose?.();
    if (create) assert.equal(options?.placement, "belowEditor");
    widget = create?.(tui, theme);
  };
  const footer = factory(tui, theme, footerData);
  assert.deepEqual(footer.render(100), [], "The native footer must not duplicate the below-editor statusline");
  assert(widget, "The statusline must mount as a below-editor widget");
  return { ...widget, dispose: () => footer.dispose() };
}

async function checkGitRefresh(theme: any): Promise<void> {
  const handlers: Record<string, any> = {};
  const probes: Array<{ signal?: AbortSignal; resolve: (status: ReturnType<typeof parseGitStatus> | undefined) => void }> = [];
  let factory: any;
  let branchChanged!: () => void;
  let branch = "main";
  let renders = 0;
  let unsubscribed = 0;
  const api: any = { on(event: string, handler: any) { handlers[event] = handler; }, getThinkingLevel: () => "off" };
  const ctx: any = {
    mode: "tui", cwd: "/tmp/project", getContextUsage: () => undefined,
    sessionManager: { getSessionId: () => "git-test", getEntryCount: () => 0, getLeafId: () => null, getEntries: () => [] },
    ui: { setFooter(next: any) { factory = next; } },
  };
  installStatusline(api, {
    readGitStatus: (cwd, signal) => {
      assert.equal(cwd, ctx.cwd);
      return new Promise((resolve) => probes.push({ signal, resolve }));
    },
  });
  handlers.session_start({}, ctx);
  const originalSetInterval = globalThis.setInterval;
  globalThis.setInterval = (() => {
    throw new Error("Git status must not install a polling timer");
  }) as any;
  let footer: any;
  try {
    footer = mountStatusline(factory, ctx, { requestRender() { renders++; } }, theme, {
      onBranchChange(callback: () => void) { branchChanged = callback; return () => { unsubscribed++; }; },
      getGitBranch: () => branch, getExtensionStatuses: () => new Map(),
    });
  } finally {
    globalThis.setInterval = originalSetInterval;
  }
  const text = () => stripTerminalSequences(footer.render(300)[0]);
  try {
    assert.equal(probes.length, 1, "Mount must request one asynchronous snapshot");
    for (const toolName of ["edit", "write", "bash", "powershell"]) handlers.tool_execution_end({ toolName }, ctx);
    assert.equal(probes.length, 1, "Parallel tool completions must not start parallel probes");
    probes[0].resolve(parseGitStatus("# branch.head main\0? stale\0"));
    await settleGit();
    assert.equal(probes.length, 2, "A burst needs only one follow-up probe");
    assert(!text().includes("?1"), "Superseded snapshots must not be displayed");
    probes[1].resolve(parseGitStatus("# branch.head main\0? one\0? two\0"));
    await settleGit();
    assert(text().includes("main [?2] |"));

    for (const toolName of ["read", "grep", "find", "ls", "mcp__docs__search"]) handlers.tool_execution_end({ toolName }, ctx);
    await settleGit();
    assert.equal(probes.length, 2, "Read-only tools and idle time must not schedule Git probes");
    handlers.before_agent_start({}, ctx);
    assert.equal(probes.length, 3, "A new task must pick up changes made outside Pi");
    ctx.mode = "rpc";
    handlers.before_agent_start({}, ctx);
    handlers.tool_execution_end({ toolName: "write" }, ctx);
    ctx.mode = "tui";
    for (let i = 0; i < 100; i++) footer.render(42);
    probes[2].resolve(undefined);
    await settleGit();
    assert.equal(probes.length, 3, "RPC events and repaints must not schedule Git probes");
    assert(text().includes("main |"), "A failed probe must remove stale status without breaking the footer");

    branch = "other";
    branchChanged();
    assert.equal(probes.length, 4);
    assert(text().includes("other |"));
    const beforeShutdown = renders;
    handlers.session_shutdown({}, ctx);
    assert(probes[3].signal?.aborted, "Shutdown must cancel the pending subprocess");
    probes[3].resolve(parseGitStatus("# branch.head other\0? late\0"));
    await settleGit();
    assert.equal(renders, beforeShutdown, "Late results must not repaint a disposed footer");
    handlers.before_agent_start({}, ctx);
    handlers.tool_execution_end({ toolName: "bash" }, ctx);
    assert.equal(probes.length, 4, "Disposed task and tool handlers must not start more probes");
  } finally {
    footer.dispose();
  }
  assert.equal(unsubscribed, 1, "Shutdown and footer disposal must be idempotent");
  console.error("Git refresh: no polling, new tasks, mutating-tool filtering, coalesced bursts, RPC guards, failures and shutdown cleanup passed");
}

async function checkGitStatus(pi: ExtensionAPI): Promise<void> {
  const synthetic = parseGitStatus([
    "# branch.head main", "# branch.ab +2 -3", "# stash 4",
    "1 MT N... staged-and-modified", "1 .D N... deleted", "u UU N... conflict",
    "2 RM N... renamed", "? original\n# stash 99", "? untracked\n1 M. fake",
  ].join("\0") + "\0");
  assert.deepEqual(synthetic, { branch: "main", conflicted: 1, staged: 2, modified: 2, renamed: 1, deleted: 1, untracked: 1, stashed: 4, ahead: 2, behind: 3 });

  const root = mkdtempSync(join(tmpdir(), "pi-git-status-"));
  const cwd = join(root, "repo");
  mkdirSync(cwd);
  const git = async (...args: string[]) => {
    const result = await pi.exec("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "core.fsmonitor=false", ...args], { cwd, timeout: 5_000 });
    assert.equal(result.code, 0, `git ${args.join(" ")}: ${result.stderr}`);
    return result.stdout.trim();
  };
  try {
    await git("init", "-b", "main");
    await git("config", "user.name", "Pi UI test");
    await git("config", "user.email", "pi-test@example.invalid");
    for (const name of ["modified", "staged", "deleted", "? original\nname"]) writeFileSync(join(cwd, name), `${name}\n`);
    await git("add", ".");
    await git("commit", "-m", "base");
    const base = await git("rev-parse", "HEAD");
    await git("branch", "upstream");
    await git("branch", "--set-upstream-to=upstream", "main");
    const clean = await readGitStatus(cwd);
    assert(clean);
    assert.equal(clean.branch, "main");
    assert(Object.entries(clean).every(([key, value]) => key === "branch" || value === 0));

    writeFileSync(join(cwd, "modified"), "worktree change\n");
    writeFileSync(join(cwd, "staged"), "index change\n");
    await git("add", "staged");
    renameSync(join(cwd, "? original\nname"), join(cwd, "renamed"));
    await git("add", "--", "? original\nname", "renamed");
    rmSync(join(cwd, "deleted"));
    writeFileSync(join(cwd, "untracked\n1 M. fake"), "untracked\n");
    const dirty = await readGitStatus(cwd);
    assert(dirty);
    assert.equal(dirty.staged, 2);
    assert.equal(dirty.modified, 1);
    assert.equal(dirty.renamed, 1);
    assert.equal(dirty.deleted, 1);
    assert.equal(dirty.untracked, 1);
    await git("stash", "push", "--include-untracked", "-m", "test stash");
    assert.equal((await readGitStatus(cwd))?.stashed, 1);
    await git("stash", "drop");

    await git("commit", "--allow-empty", "-m", "ahead");
    assert.equal((await readGitStatus(cwd))?.ahead, 1);
    await git("switch", "upstream");
    await git("commit", "--allow-empty", "-m", "behind one");
    await git("commit", "--allow-empty", "-m", "behind two");
    await git("switch", "main");
    const diverged = await readGitStatus(cwd);
    assert.equal(diverged?.ahead, 1);
    assert.equal(diverged?.behind, 2);

    writeFileSync(join(cwd, "modified"), "main side\n");
    await git("add", "modified");
    await git("commit", "-m", "main change");
    await git("switch", "upstream");
    writeFileSync(join(cwd, "modified"), "upstream side\n");
    await git("add", "modified");
    await git("commit", "-m", "upstream change");
    await git("switch", "main");
    const merge = await pi.exec("git", ["-c", "core.hooksPath=/dev/null", "merge", "upstream"], { cwd, timeout: 5_000 });
    assert.equal(merge.code, 1, "Fixture must produce a merge conflict");
    const conflicted = await readGitStatus(cwd);
    assert.equal(conflicted?.conflicted, 1);
    assert.equal(conflicted?.staged, 0, "Conflicts must not count as ordinary staged files");
    assert.equal(conflicted?.modified, 0);
    await git("merge", "--abort");
    await git("switch", "--detach", base);
    assert.equal((await readGitStatus(cwd))?.branch, "HEAD");
    assert.equal(await readGitStatus(root), undefined, "Non-repositories must quietly omit status");
    assert.equal(await readGitStatus(cwd, AbortSignal.abort()), undefined, "Cancelled probes must quietly stop");
    console.error("Git status: NUL paths, staged/worktree changes, renames, deletions, stash, divergence, conflicts and detached HEAD passed");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function balancePayload(available_usd: string | null, exhausted = available_usd !== null && !/[1-9]/.test(available_usd)) {
  return { schema: "rewind.balance.v1", currency: "USD", available_usd, exhausted, as_of: "2026-11-08T12:34:56.123Z" };
}

async function checkBalanceReader(): Promise<void> {
  assert.equal(formatBalance(null), undefined);
  assert.equal(formatBalance("0"), "$0.00");
  assert.equal(formatBalance("0.00000001"), "<$0.01");
  assert.equal(formatBalance("0.00999999"), "<$0.01");
  assert.equal(formatBalance("0.01"), "$0.01");
  assert.equal(formatBalance("12.345"), "$12.35");
  assert.equal(formatBalance("999999999999.99999999"), "$1000000000000.00");
  assert(parseBalanceResponse(balancePayload("12.34")));
  assert(parseBalanceResponse({ ...balancePayload("1"), as_of: "2026-11-08T20:34:56+08:00" }));
  for (const payload of [
    null, [], {},
    { ...balancePayload("1"), schema: "other" },
    { ...balancePayload("1"), currency: "EUR" },
    { ...balancePayload("1"), available_usd: -1 },
    balancePayload("-1"), balancePayload("1234567890123"), balancePayload("1.123456789"),
    { ...balancePayload("0"), exhausted: false }, { ...balancePayload("1"), exhausted: true },
    { ...balancePayload(null), exhausted: true },
    { ...balancePayload("1"), as_of: "not-a-date" },
    { ...balancePayload("1"), as_of: "2026-02-30T12:00:00Z" },
  ]) assert.equal(parseBalanceResponse(payload), undefined, `Malformed balance accepted: ${JSON.stringify(payload)}`);

  let fetches = 0;
  let seenAuthorization = "";
  const reader = createBalanceReader({
    readFile: async (path, options) => {
      assert.equal(path, "/run/secret/client-key");
      assert(!options.signal?.aborted);
      return "client-api-key\n";
    },
    fetch: (async (_url: URL, init: RequestInit) => {
      fetches++;
      assert.equal(init.method, "GET");
      assert.equal(init.redirect, "manual");
      seenAuthorization = new Headers(init.headers).get("authorization") ?? "";
      return new Response(JSON.stringify(balancePayload("12.34")), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
  });
  const config = { url: "http://gizmo:8318/rewind/balance", apiKeyFile: "/run/secret/client-key" };
  assert.equal((await reader(config))?.availableUsd, "12.34");
  assert.equal(fetches, 1);
  assert.equal(seenAuthorization, "Bearer client-api-key");

  const responseReader = (response: Response) => createBalanceReader({
    readFile: async () => "key",
    fetch: (async () => response) as typeof fetch,
  })(config);
  assert.equal(await responseReader(new Response("redirect", { status: 302, headers: { location: "https://example.invalid" } })), undefined);
  assert.equal(await responseReader(new Response("x", { status: 500 })), undefined);
  assert.equal(await responseReader(new Response("not-json", { status: 200 })), undefined);
  assert.equal(await responseReader(new Response(JSON.stringify(balancePayload("1")), { status: 200, headers: { "content-length": "999999" } })), undefined);
  assert.equal(await createBalanceReader({ readFile: async () => "key", fetch: (async () => {
    return new Response("x".repeat(32), { status: 200 });
  }) as typeof fetch, maxBytes: 16 })(config), undefined);
  assert.equal(await createBalanceReader({ readFile: async () => "key", fetch: (async () => {
    throw new Error("offline");
  }) as typeof fetch })(config), undefined);
  console.error("Balance reader: auth-file use, strict schema/money/time validation, bounded bodies, redirects, errors and formatting passed");
}

async function checkBalanceStatusline(theme: any): Promise<void> {
  const handlers: Record<string, any> = {};
  const probes: Array<{ signal?: AbortSignal; resolve: (snapshot: BalanceSnapshot | undefined) => void }> = [];
  const timers: Array<{ callback: () => void; cleared: boolean }> = [];
  let factory: any;
  let renders = 0;
  let reads = 0;
  const api: any = { on(event: string, handler: any) { handlers[event] = handler; }, getThinkingLevel: () => "off" };
  const rewind = { provider: "cliproxy", id: "rewind/claude", contextWindow: 128_000 };
  const ctx: any = {
    mode: "rpc", cwd: "/tmp/project", model: rewind, getContextUsage: () => undefined,
    sessionManager: { getEntries() { throw new Error("Balance rendering must not read session history"); } },
    ui: { setFooter(next: any) { factory = next; } },
  };
  installStatusline(api, {
    balance: { url: "http://gizmo:8318/rewind/balance", apiKeyFile: "/run/secret/client-key" },
    readGitStatus: async () => undefined,
    readBalance: (_config, signal) => {
      reads++;
      return new Promise((resolve) => probes.push({ signal, resolve }));
    },
    scheduleBalanceRefresh: (callback) => {
      const timer = { callback, cleared: false };
      timers.push(timer);
      return () => { timer.cleared = true; };
    },
  });
  assert.deepEqual(Object.keys(handlers).sort(), ["agent_end", "before_agent_start", "model_select", "session_shutdown", "session_start", "tool_execution_end"],
    "Balance-only mode must register one composed lifecycle handler per event and no timing handlers");
  handlers.session_start({}, ctx);
  handlers.agent_end({}, ctx);
  handlers.model_select({ model: rewind }, ctx);
  assert.equal(reads, 0, "RPC sessions/events must not read balance");

  ctx.mode = "tui";
  handlers.session_start({}, ctx);
  const footer = mountStatusline(factory, ctx, { requestRender() { renders++; } }, theme, {
    onBranchChange: () => () => {}, getGitBranch: () => undefined, getExtensionStatuses: () => new Map(),
  });
  const text = () => stripTerminalSequences(footer.render(300)[0]);
  assert.equal(reads, 1, "Mounting an applicable model must read once");
  for (let i = 0; i < 100; i++) footer.render(i % 2 ? 1 : 42);
  assert.equal(reads, 1, "Rendering and narrow widths must not read balance");
  probes[0].resolve(parseBalanceResponse(balancePayload("12.34")));
  await settleGit();
  assert(text().endsWith("bal $12.34"), text());
  assert(footer.render(300)[0].includes(theme.fg("text", "$12.34")), "Balance must follow the current theme");
  for (const width of [1, 5, 12, 42]) assert(footer.render(width).every((line: string) => visibleWidth(line) <= width));

  timers.at(-1)?.callback();
  assert.equal(reads, 2, "Periodic refresh must run while applicable");
  handlers.agent_end({}, ctx);
  handlers.agent_end({}, ctx);
  assert.equal(reads, 2, "Task-end bursts must coalesce behind the pending request");
  probes[1].resolve(parseBalanceResponse(balancePayload("0")));
  await settleGit();
  assert.equal(reads, 3, "A coalesced refresh must run once after the pending request");
  probes[2].resolve(parseBalanceResponse(balancePayload("999999999999.99999999")));
  await settleGit();
  assert(text().endsWith("bal $1000000000000.00"), text());

  timers.at(-1)?.callback();
  assert.equal(reads, 4);
  probes[3].resolve(parseBalanceResponse(balancePayload("0")));
  await settleGit();
  assert(text().endsWith("bal $0.00"), "Explicit zero balance must be displayed");
  timers.at(-1)?.callback();
  assert.equal(reads, 5);
  const stale = probes[4];
  ctx.model = { provider: "cliproxy", id: "other/model" };
  handlers.model_select({ model: ctx.model }, ctx);
  assert(stale.signal?.aborted, "Model switches must abort pending reads");
  assert(!text().includes("bal "), "A model switch must clear balance immediately");
  assert.equal(reads, 5, "Non-Rewind CLIProxy models must not read balance");
  for (const prefix of ["rewind2", "rewind3", "rewind4"]) {
    ctx.model = { provider: "cliproxy", id: `${prefix}/gpt-6-astra` };
    handlers.model_select({ model: ctx.model }, ctx);
    handlers.agent_end({}, ctx);
    assert.equal(reads, 5, `${prefix} must not read the original credential's balance`);
    assert(!text().includes("bal "), `${prefix} must not display the original credential's balance`);
  }
  ctx.model = { provider: "ninfer", id: "rewind/claude" };
  handlers.model_select({ model: ctx.model }, ctx);
  assert.equal(reads, 5, "Non-CLIProxy providers must not read balance");
  ctx.model = rewind;
  handlers.model_select({ model: rewind }, ctx);
  assert.equal(reads, 6);
  stale.resolve(parseBalanceResponse(balancePayload("88")));
  probes[5].resolve(parseBalanceResponse(balancePayload("0.00000001")));
  await settleGit();
  assert(text().endsWith("bal <$0.01"), "A->B->A stale responses must not overwrite the current generation");

  timers.at(-1)?.callback();
  probes[6].resolve(undefined);
  await settleGit();
  assert(!text().includes("bal "), "Errors must omit balance rather than preserve/fake a value");
  timers.at(-1)?.callback();
  probes[7].resolve(parseBalanceResponse(balancePayload(null)));
  await settleGit();
  assert(!text().includes("bal "), "An unbounded account balance must be omitted");
  timers.at(-1)?.callback();
  const shutdown = probes[8];
  const beforeShutdown = renders;
  handlers.session_shutdown({}, ctx);
  assert(shutdown.signal?.aborted, "Shutdown must abort the balance request");
  assert(timers.every((timer) => timer.cleared), "Model switches and shutdown must clear periodic timers");
  shutdown.resolve(parseBalanceResponse(balancePayload("44")));
  await settleGit();
  assert.equal(renders, beforeShutdown, "Late balance results must not repaint after shutdown");
  footer.dispose();
  console.error("Balance statusline: applicability, mount/task/periodic refresh, coalescing, generation guards, null/error omission and cleanup passed");
}

export default function (pi: ExtensionAPI) {
  pi.on("session_start", async (_event, host) => {
    try {
      const agent = process.env.PI_CODING_AGENT_DIR;
      assert(agent);
      const names = Object.keys(JSON.parse(readFileSync(join(agent, "themes.json"), "utf8")));
      let renders = 0;
      const tui: any = { mode: "fullscreen", terminal: { rows: 30, columns: 100 }, requestRender() { renders++; } };
      const keybindings: any = { matches: (data: string, action: string) => data === "\x1b" && action === "app.interrupt" };
      const gray = foregroundAnsi(parseColor("#c5c5c5"), getTerminalColorMode());
      const handlers: Record<string, any> = {};
      let editorFactory: any;
      let footerFactory: any;
      const api: any = {
        on(event: string, handler: any) { handlers[event] = handler; },
        getThinkingLevel: () => "xhigh",
      };
      const model: any = { id: "model-test", reasoning: true, contextWindow: 128_000 };
      let usage: any = { tokens: 38_400, contextWindow: 128_000, percent: 30 };
      let entriesReads = 0;
      const entries: any[] = [
        { type: "message", message: { role: "assistant", usage: { cost: { total: 1.25 } } } },
        { type: "message", message: { role: "toolResult", usage: { cost: { total: 2 } } } },
        { type: "custom", usage: { cost: { total: 0.75 } } },
        { type: "message", message: { role: "user", usage: { cost: { total: 99 } } } },
        { type: "custom", usage: { cost: { total: -1 } } },
      ];
      const ctx: any = {
        mode: "rpc", cwd: "/tmp/project", model,
        getContextUsage: () => usage,
        sessionManager: {
          getSessionId: () => "ui-test", getEntryCount: () => entries.length, getLeafId: () => "leaf",
          getEntries() { entriesReads++; return entries; },
        },
        ui: {
          theme: host.ui.theme,
          setEditorComponent(factory: any) { editorFactory = factory; },
          setFooter(factory: any) { footerFactory = factory; },
        },
      };
      installPrompt(api);
      const startPrompt = handlers.session_start;
      let clock = 1_000;
      let gitReads = 0;
      let gitSnapshot = parseGitStatus(["# branch.head main", "# branch.ab +1 -2", "1 M. staged", "1 M. staged-again", "1 .M modified", "? one", "? two", "? three", ""].join("\0"));
      installStatusline(api, {
        showTokenRate: true, now: () => clock,
        readGitStatus: async () => { gitReads++; return gitSnapshot; },
      });
      const startStatusline = handlers.session_start;
      await startPrompt({}, ctx);
      await startStatusline({}, ctx);
      assert.equal(editorFactory, undefined, "RPC must not install a terminal editor");
      assert.equal(footerFactory, undefined, "RPC must not install a terminal footer");
      assert.equal(gitReads, 0, "RPC must not start Git probes");
      ctx.mode = "tui";
      await startPrompt({}, ctx);
      await startStatusline({}, ctx);
      assert.equal(typeof editorFactory, "function");
      assert.equal(typeof footerFactory, "function");
      initTheme("evergarden-winter");
      const editorTheme = { borderColor: (text: string) => host.ui.theme.fg("border", text), selectList: getSelectListTheme() };
      const editor = editorFactory(tui, editorTheme, keybindings);
      const native = new CustomEditor(tui, editorTheme, keybindings, { paddingX: 2, embedWorkingStatus: true });
      editor.focused = native.focused = true;
      editor.setWorkingStatusIndicator({
        renderInBorder: () => editor.borderColor("Working..."),
        renderSpinnerInBorder: () => editor.borderColor("·"),
      });
      native.setWorkingStatusIndicator({
        renderInBorder: () => native.borderColor("Working..."),
        renderSpinnerInBorder: () => native.borderColor("·"),
      } as any);
      let branchChanged!: () => void;
      let disposed = 0;
      const footerData: any = {
        onBranchChange(callback: () => void) { branchChanged = callback; return () => { disposed++; }; },
        getGitBranch: () => "main",
        getExtensionStatuses: () => new Map([["z", "second\nstatus"], ["a", "first\tstatus"]]),
      };
      const footer = mountStatusline(footerFactory, ctx, tui, host.ui.theme, footerData);
      await settleGit();
      let previousFooter: string | undefined;
      let previousPalette: string | undefined;

      for (const name of names) {
        initTheme(name);
        for (const mode of ["fullscreen", "regular"]) {
          tui.mode = mode;
          for (const level of ["off", "xhigh", "max", "bash"]) {
            const color = level === "bash" ? host.ui.theme.getBashModeBorderColor() : host.ui.theme.getThinkingBorderColor(level as any);
            for (const padding of [0, 2, 4]) {
              editor.setPaddingX(padding);
              native.setPaddingX(Math.max(2, padding));
              for (const text of ["", "中文🙂\nsecond line", "word ".repeat(50)]) {
                editor.setText(text);
                native.setText(text);
                for (const width of [1, 2, 5, 12, 42, 100]) {
                  const actualPadding = Math.min(editor.getPaddingX(), Math.max(0, Math.floor((width - 1) / 2)));
                  // Native Editor needs room for its cursor and double-width graphemes.
                  if (width === 1 && text.length > 0) continue;
                  if (text.includes("中文") && width - 2 * actualPadding - (actualPadding ? 0 : 1) < 2) continue;
                  editor.borderColor = color;
                  native.borderColor = color;
                  const lines = editor.render(width);
                  const plain = lines.map(stripTerminalSequences);
                  const expected = native.render(width).map(stripTerminalSequences);
                  if (actualPadding >= 2 && expected[1] !== undefined) {
                    expected[1] = " ".repeat(actualPadding - 2) + "❯ " + expected[1].slice(actualPadding);
                  }
                  assert.deepEqual(plain, expected, `${name}: editor geometry or contents changed`);
                  assert(lines.every((line: string) => visibleWidth(line) <= width), `${name}/${level}: editor exceeded ${width} columns (padding ${padding}, text ${JSON.stringify(text)}, widths ${lines.map(visibleWidth)})`);
                  const foregrounds = lines.join("").match(/\x1b\[(?:38;[^m]+|3[0-7]|9[0-7])m/g) ?? [];
                  assert(foregrounds.length > 0);
                  assert(foregrounds.every((sequence: string) => sequence === gray), `${name}/${level}: editor is not fixed gray-white`);
                  assert(!/\x1b\[(?:48;[^m]+|4[0-7]|10[0-7])m/.test(lines.join("")), "Editor background must remain terminal default");
                  assert.equal(lines.join("").split(CURSOR_MARKER).length - 1, 1, "IME cursor marker moved or disappeared");
                  assert.equal(editor.getText(), native.getText());
                  assert.deepEqual(editor.getCursor(), native.getCursor());
                }
              }
            }
          }
        }

        usage = { tokens: 38_400, contextWindow: 128_000, percent: 30 };
        const lines = footer.render(300);
        const output = stripTerminalSequences(lines[0]);
        assert(output.includes("main [+2 !1 ?3 ↑1 ↓2] | model-test xhigh | ctx 38.4k/128k (30%)"), output);
        assert(!output.includes("$4.00"), "Historical session cost must be removed from the statusline");
        for (const [marker, color] of [["+2", "success"], ["!1", "warning"], ["?3", "muted"], ["↑1", "success"], ["↓2", "warning"]]) {
          assert(lines[0].includes(host.ui.theme.fg(color as any, marker)), `${name}: Git status must follow the theme`);
        }
        assert.equal(stripTerminalSequences(lines[1]), "first status second status");
        assert(lines[0].includes(host.ui.theme.fg("accent", "model-test")));
        assert(lines[0].includes(host.ui.theme.fg("mdLink", "/tmp/project")));
        assert(lines[0].includes(host.ui.theme.fg("dim", "|")));
        assert(lines[1].includes(host.ui.theme.fg("muted", "first status")));
        const palette = ["accent", "mdLink", "text", "dim", "success", "muted"].map((token) => host.ui.theme.getFgAnsi(token as any)).join("");
        if (previousFooter && palette !== previousPalette) assert.notEqual(lines[0], previousFooter, "Footer retained the previous theme's ANSI colors");
        previousFooter = lines[0];
        previousPalette = palette;
        for (const percent of [0, 75, 95, 110]) {
          usage = { tokens: percent / 100 * 128_000, contextWindow: 128_000, percent };
          const colored = footer.render(300)[0];
          const color = percent >= 90 ? "error" : percent >= 70 ? "warning" : "success";
          assert(colored.includes(host.ui.theme.fg(color, `(${percent}%)`)));
        }
        usage = { tokens: null, contextWindow: 128_000, percent: null };
        assert(stripTerminalSequences(footer.render(300)[0]).endsWith("ctx ?/128k"));
        usage = { tokens: 1_024_000, contextWindow: 1_280_000, percent: null };
        assert(stripTerminalSequences(footer.render(300)[0]).includes("ctx 1.02M/1.28M (80%)"));
        for (const width of [1, 12, 42, 100]) assert(footer.render(width).every((line: string) => visibleWidth(line) <= width));
        console.error(`${name}: fixed gray-white editor, cursor/geometry, themed footer and context states passed (${host.ui.theme.getColorMode()})`);
      }
      assert.equal(entriesReads, 0, "Statusline rendering must never scan historical session usage");
      assert.equal(gitReads, 1, "Repaints must not invoke Git");
      const footerText = () => stripTerminalSequences(footer.render(300)[0]);
      gitSnapshot = parseGitStatus("# branch.head main\0");
      handlers.tool_execution_end({ toolName: "write" }, ctx);
      await settleGit();
      assert(footerText().includes("main | model-test"), "Clean repositories must not show brackets");
      gitSnapshot = parseGitStatus("# branch.head other\0? file\0");
      handlers.tool_execution_end({ toolName: "bash" }, ctx);
      await settleGit();
      assert(footerText().includes("main | model-test"), "Do not show an old snapshot beside a different branch");
      const startTurn = () => handlers.turn_start({ type: "turn_start", turnIndex: 0, timestamp: clock }, ctx);
      const finishMessage = (output: unknown, stopReason = "stop", role = "assistant") => handlers.message_end({
        type: "message_end", message: { role, stopReason, usage: { output, input: 999_999, cacheRead: 999_999, cacheWrite: 999_999 } },
      }, ctx);
      assert(!footerText().includes("tok/s"), "No rate should be invented from historical usage without timing");
      startTurn();
      assert(footerText().endsWith("avg … tok/s"));
      clock = 4_000;
      finishMessage(99_999, "stop", "toolResult");
      assert(footerText().includes("avg … tok/s"), "Tool-owned usage must not count as assistant output");
      finishMessage(120);
      assert(footerText().endsWith("avg 40 tok/s"), "Rate must use actual output tokens, not input/cache counts");
      for (const name of names) {
        initTheme(name);
        assert(footer.render(300)[0].includes(host.ui.theme.fg("text", "40")), `${name}: rate must follow the current theme`);
      }
      clock = 44_000;
      handlers.agent_end({}, ctx);
      assert(footerText().includes("avg 40 tok/s"), "Idle/tool time must not dilute the completed reply's rate");
      startTurn();
      clock = 45_000;
      finishMessage(50);
      assert(footerText().includes("avg 50 tok/s"), "Each model reply must have an independent rate");
      handlers.model_select({}, ctx);
      assert(!footerText().includes("tok/s"), "Changing models must not keep the previous model's rate");
      for (const stopReason of ["error", "aborted"]) {
        startTurn();
        clock += 1_000;
        finishMessage(1, stopReason);
        assert(!footerText().includes("tok/s"), "Failed replies may contain placeholder usage, not a real final token count");
      }
      for (const output of [undefined, 0, -1, NaN, Infinity]) {
        startTurn();
        clock += 1_000;
        finishMessage(output);
        assert(!footerText().includes("tok/s"), "Missing/invalid output usage must not become a fake rate");
      }
      startTurn();
      finishMessage(10);
      assert(!footerText().includes("tok/s"), "Zero elapsed time must not produce Infinity");
      startTurn();
      handlers.agent_end({}, ctx);
      assert(!footerText().includes("tok/s"), "An aborted run without message_end must clear the pending rate");
      ctx.mode = "rpc";
      startTurn();
      ctx.mode = "tui";
      assert(!footerText().includes("tok/s"), "RPC events must not start a terminal rate meter");
      startTurn();
      handlers.session_shutdown({}, ctx);
      assert(!footerText().includes("tok/s"), "Reload/session replacement must clear timing state");
      assert.equal(entriesReads, 0, "Rate events must not scan recorded usage");
      for (const options of [{}, { showTokenRate: false }]) {
        const disabledHandlers: Record<string, any> = {};
        let disabledFooterFactory: any;
        const disabledCtx = {
          ...ctx,
          sessionManager: { ...ctx.sessionManager, getEntries: () => entries },
          ui: { ...ctx.ui, setFooter(factory: any) { disabledFooterFactory = factory; } },
        };
        installStatusline({ ...api, on(event: string, handler: any) { disabledHandlers[event] = handler; } }, {
          ...options, readGitStatus: async () => undefined,
          now: () => { throw new Error("Disabled token-rate meter must not collect timing"); },
        });
        assert.deepEqual(Object.keys(disabledHandlers).sort(), ["before_agent_start", "session_shutdown", "session_start", "tool_execution_end"], "tok/s must not register timing handlers when disabled");
        disabledHandlers.session_start({}, disabledCtx);
        const disabledFooter = mountStatusline(disabledFooterFactory, disabledCtx, tui, host.ui.theme, { ...footerData, onBranchChange: () => () => {} });
        assert(!stripTerminalSequences(disabledFooter.render(300)[0]).includes("tok/s"));
        disabledFooter.dispose();
      }
      console.error("tok/s: disabled defaults, exact output usage, frozen/per-reply averages, themes, cancellation and missing-data cases passed");
      const beforeRender = renders;
      branchChanged();
      assert.equal(renders, beforeRender + 1);
      footer.dispose();
      await settleGit();
      assert.equal(renders, beforeRender + 1, "Disposal must prevent late probe results from repainting");
      assert.equal(disposed, 1, "Shutdown and disposal must unsubscribe only once");
      await checkGitRefresh(host.ui.theme);
      await checkGitStatus(pi);
      await checkBalanceReader();
      await checkBalanceStatusline(host.ui.theme);
      let submitted = "";
      editor.onSubmit = (text: string) => { submitted = text; };
      editor.setText("message");
      editor.render(80);
      editor.handleInput("\r");
      assert.equal(submitted, "message", "Rendering must not insert ANSI or the prompt prefix into submissions");
      let escaped = false;
      editor.onEscape = () => { escaped = true; };
      editor.handleInput("\x1b");
      assert(escaped, "CustomEditor app keybindings must remain wired");
      console.error("Pi editor/statusline checks passed (offline; no home activation)");
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
    host.shutdown();
  });
}
