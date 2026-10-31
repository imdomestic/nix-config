import { UserMessageComponent, type ExtensionAPI, type Theme } from "@earendil-works/pi-coding-agent";
import { stripTerminalSequences } from "@earendil-works/pi-tui";

type RendererExtension = (pi: ExtensionAPI) => void;

function installUserMessagePrefix(getTheme: () => Theme): () => void {
  const original = UserMessageComponent.prototype.render;
  let active = true;
  const render = function (this: UserMessageComponent, width: number): string[] {
    if (!active || width <= 2) return original.call(this, width);
    const theme = getTheme();
    let first = true;
    // Reserve a gutter after Markdown layout, without changing message text or syntax.
    return original.call(this, width - 2).map((line) => {
      const content = stripTerminalSequences(line).trim().length > 0;
      const prefix = first && content ? theme.fg("userMessageText", "❯ ") : "  ";
      if (content) first = false;
      // Keep Pi's prompt-zone markers at the start of the line.
      const markers = line.match(/^(?:\x1b\]133;[^\x07]*\x07)*/)?.[0] ?? "";
      return markers + theme.bg("userMessageBg", prefix) + line.slice(markers.length);
    });
  };
  UserMessageComponent.prototype.render = render;
  return () => {
    active = false;
    if (UserMessageComponent.prototype.render === render) UserMessageComponent.prototype.render = original;
  };
}

export function installRenderers(pi: ExtensionAPI, cc: RendererExtension, better: RendererExtension): void {
  let disposePrefix: (() => void) | undefined;
  // Install below CC's sticky-prompt patch, and remove it after CC's teardown.
  pi.on("session_start", (_event, ctx) => {
    if (ctx.mode === "tui") disposePrefix = installUserMessagePrefix(() => ctx.ui.theme);
  });
  const starts: Array<(...args: any[]) => unknown> = [];
  // Register better's teardown first, but install its patch after CC settles.
  // See docs/incidents.md#pi-renderer-lifecycle.
  better({
    ...pi,
    on(event, handler) {
      if (event !== "session_start") return pi.on(event, handler);
      starts.push(handler);
      return () => {
        const index = starts.indexOf(handler);
        if (index !== -1) starts.splice(index, 1);
      };
    },
  } as ExtensionAPI);
  const stops: Array<(...args: any[]) => unknown> = [];
  cc({
    ...pi,
    on(event, handler) {
      if (event !== "session_shutdown") return pi.on(event, handler);
      stops.push(handler);
      return () => {
        const index = stops.indexOf(handler);
        if (index !== -1) stops.splice(index, 1);
      };
    },
  } as ExtensionAPI);
  pi.on("session_start", async (event, ctx) => {
    if (ctx.mode !== "tui") return;
    await new Promise((resolve) => setTimeout(resolve, 0));
    for (const handler of starts) await handler(event, ctx);
  });
  pi.on("session_shutdown", async (event, ctx) => {
    try {
      for (const handler of [...stops].reverse()) await handler(event, ctx);
    } finally {
      disposePrefix?.();
      disposePrefix = undefined;
    }
  });
}
