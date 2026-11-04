import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import installPrompt from "./prompt-prefix.ts";
import { installRenderers } from "./render.ts";
import installStatusline from "./statusline.ts";
import type { BalanceConfig } from "./balance.ts";

type Extension = (pi: ExtensionAPI) => void;
type Extensions = { cc: Extension; better: Extension; subagents: Extension };
export type Options = { showTokenRate?: boolean; balance?: BalanceConfig };

export default function bootstrap(pi: ExtensionAPI, extensions: Extensions, options: Options = {}): void {
  process.env.PI_BETTER_RENDER_MERMAID_INSTALL ??= "0";
  process.env.PI_BETTER_RENDER_FONT_DOWNLOAD ??= "0";

  installRenderers(pi, extensions.cc, extensions.better);
  installPrompt(pi);
  // Below-editor widgets retain registration order: statusline, then FleetView.
  installStatusline(pi, options);
  extensions.subagents(pi);
}
