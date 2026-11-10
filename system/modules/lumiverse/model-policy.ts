import type { LlmProvider } from "./provider";

const prefixes = (process.env.LUMIVERSE_EXCLUDED_MODEL_PREFIXES || "")
  .split(",").map(value => value.trim().toLowerCase()).filter(Boolean);

export function isExcludedModel(model: unknown): boolean {
  return typeof model === "string"
    && prefixes.some(prefix => model.trim().toLowerCase().startsWith(prefix));
}

/** Apply the deployment policy to discovery and both native generation paths. */
export function enforceModelPolicy(provider: LlmProvider): LlmProvider {
  const generate = provider.generate.bind(provider);
  const generateStream = provider.generateStream.bind(provider);
  const listModels = provider.listModels.bind(provider);
  const check = (model: unknown) => {
    if (isExcludedModel(model)) {
      throw new Error("This conditional-use model provider is excluded from this deployment.");
    }
  };
  provider.generate = async (key, url, request) => {
    check(request.model);
    return generate(key, url, request);
  };
  provider.generateStream = async function* (key, url, request) {
    check(request.model);
    yield* generateStream(key, url, request);
  };
  provider.listModels = async (key, url) => (await listModels(key, url))
    .filter(model => !isExcludedModel(model));
  return provider;
}
