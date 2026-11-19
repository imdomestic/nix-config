import { googleGenerativeAIApi, type Api, type Model, type SimpleStreamOptions, type TranscriptContext } from "@earendil-works/pi-ai/compat";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function installAgyXHigh(pi: ExtensionAPI): void {
  pi.registerProvider("agy", {
    api: "agy-google-xhigh",
    streamSimple(model: Model<Api>, context: TranscriptContext, options?: SimpleStreamOptions) {
      if (model.provider !== "agy" || model.id !== "gemini-4-hydrogen-xhigh" || options?.reasoning !== "xhigh") {
        throw new Error("agy-google-xhigh requires the Hydrogen XHigh model and xhigh thinking");
      }
      // Pi 1.5.2 accepts only through HIGH; delegate all other Gemini behavior unchanged.
      const nativeModel = { ...model, api: "google-generative-ai" as const, thinkingLevelMap: { ...model.thinkingLevelMap, xhigh: "high" } };
      return googleGenerativeAIApi().streamSimple(nativeModel, context, {
        ...options,
        onPayload: async (payload) => {
          const changed = await options.onPayload?.(payload, model);
          const request = (changed === undefined ? payload : changed) as { config?: { thinkingConfig?: { thinkingLevel?: string } } } | null;
          const thinking = request?.config?.thinkingConfig;
          if (thinking?.thinkingLevel !== "HIGH") throw new Error("Unexpected Pi Google thinking payload for agy Hydrogen XHigh");
          return { ...request, config: { ...request?.config, thinkingConfig: { ...thinking, thinkingLevel: "XHIGH" } } };
        },
      });
    },
  });
}
