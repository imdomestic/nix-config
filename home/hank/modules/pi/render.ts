import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

type RendererExtension = (pi: ExtensionAPI) => void;

export function installRenderers(pi: ExtensionAPI, cc: RendererExtension, better: RendererExtension): void {
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
    for (const handler of [...stops].reverse()) await handler(event, ctx);
  });
}
