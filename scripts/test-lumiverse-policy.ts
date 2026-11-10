// Run with the pinned image's Bun and mount this at /app/test-model-policy.ts.
import { expect, test } from "bun:test";
import { getProvider, getProviderList } from "./src/llm/registry";
import { enforceModelPolicy } from "./src/llm/model-policy";

test("every registered provider rejects Rewind before networking", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (() => { calls++; throw new Error("Unexpected network access"); }) as any;
  try {
    for (const provider of getProviderList()) {
      const request = { model: " ReWiNd/gpt-6-astra ", messages: [] };
      await expect(provider.generate("not-required", "http://unreachable.invalid", request))
        .rejects.toThrow("excluded from this deployment");
      await expect(provider.generateStream("not-required", "http://unreachable.invalid", request).next())
        .rejects.toThrow("excluded from this deployment");
    }
    expect(calls).toBe(0);
  } finally { globalThis.fetch = originalFetch; }
});

test("policy preserves provider identity, context, stream and errors", async () => {
  const original = {
    name: "fixture", marker: "same-instance",
    async generate() { return { content: this.marker }; },
    async *generateStream() { yield { content: this.marker }; },
    async listModels() { return ["rewind/model", "bonsai-hikari", "gpt-6.1-sol"]; },
  };
  const wrapped = enforceModelPolicy(original as any);
  expect(wrapped).toBe(original as any);
  expect(await wrapped.listModels("", "")).toEqual(["bonsai-hikari", "gpt-6.1-sol"]);
  expect((await wrapped.generate("", "", { model: "bonsai-hikari", messages: [] })).content).toBe("same-instance");
  expect((await wrapped.generateStream("", "", { model: "bonsai-hikari", messages: [] }).next()).value?.content).toBe("same-instance");
});

test("actual Custom catalog filters only excluded models", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => Response.json({ data: [
    { id: "rewind/gpt-6-astra" }, { id: "gpt-6.1-sol" }, { id: "bonsai-main" },
  ] })) as any;
  try {
    expect(await getProvider("custom")!.listModels("not-required", "http://fixture.invalid/v1"))
      .toEqual(["bonsai-main", "gpt-6.1-sol"]);
  } finally { globalThis.fetch = originalFetch; }
});
