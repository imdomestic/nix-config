import { CustomEditor, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { getTerminalColorMode, parseColor, styleText } from "@earendil-works/pi-tui";

const inputColor = parseColor("#c5c5c5");
const grayWhite = (text: string) => styleText(text, { fg: inputColor }, getTerminalColorMode());

class PromptPrefixEditor extends CustomEditor {
  override setPaddingX(padding: number): void {
    super.setPaddingX(Math.max(2, padding));
  }

  override render(width: number): string[] {
    // Pi rewrites borderColor on thinking/bash changes; keep this editor neutral.
    this.borderColor = grayWhite;
    const lines = super.render(width);
    const padding = Math.min(this.getPaddingX(), Math.max(0, Math.floor((width - 1) / 2)));

    // Draw inside the editor's padding so text, cursor and mouse geometry agree.
    if (padding >= 2 && lines[1] !== undefined) {
      lines[1] = " ".repeat(padding - 2) + "❯ " + lines[1].slice(padding);
    }
    return lines.map(grayWhite);
  }
}

export default function (pi: ExtensionAPI) {
  pi.on("session_start", (_event, ctx) => {
    if (ctx.mode !== "tui") return;
    ctx.ui.setEditorComponent((tui, theme, keybindings) =>
      new PromptPrefixEditor(tui, theme, keybindings, { paddingX: 2, embedWorkingStatus: true }),
    );
  });
}
