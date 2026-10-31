// Run in an isolated Pi process; see docs/decisions.md#pi-magic-context.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default async function (pi: ExtensionAPI) {
  const packagePath = process.env.PI_MAGIC_CONTEXT_PACKAGE;
  assert(packagePath);
  const definitions = new Map<string, any>();
  const { default: magicContext } = await import(`${packagePath}/dist/index.js`);
  await magicContext({
    ...pi,
    registerTool(tool: any) {
      definitions.set(tool.name, tool);
      pi.registerTool(tool);
    },
  });
  pi.on("session_start", async (_event, ctx) => {
    try {
      const require = createRequire(`${packagePath}/package.json`);
      assert.equal(typeof require("onnxruntime-node").InferenceSession, "function");
      assert.equal(typeof require("sharp"), "function");
      assert.equal(pi.getSettings().compaction?.enabled, false);
      const tools = pi.getAllTools().map((tool) => tool.name);
      for (const name of ["ctx_search", "ctx_memory", "ctx_note", "ctx_expand", "ctx_reduce"]) {
        assert(tools.includes(name), `Missing Magic Context tool: ${name}`);
      }
      const commands = pi.getCommands().map((command) => command.name);
      for (const name of ["ctx-status", "ctx-flush", "ctx-wrapup", "ctx-recomp", "ctx-dream"]) {
        assert(commands.includes(name), `Missing Magic Context command: ${name}`);
      }
      const model = ctx.modelRegistry.find("cliproxy", "gpt-5.5");
      assert(model, "The configured historian model must be registered in Pi");
      assert(existsSync(`${process.env.MAGIC_CONTEXT_STORAGE_DIR}/context.db`));
      const written = await definitions.get("ctx_memory").execute("smoke-memory", {
        action: "write", category: "CONFIG_VALUES", content: "smokemarker verifies isolated Magic Context memory storage.",
      }, undefined, undefined, ctx);
      assert(!written.isError, JSON.stringify(written));
      const searched = await definitions.get("ctx_search").execute("smoke-search", { query: "smokemarker" }, undefined, undefined, ctx);
      assert(!searched.isError, JSON.stringify(searched));
      assert(searched.content.some((part: any) => part.type === "text" && part.text.includes("smokemarker")), "Stored memory was not searchable");
      console.error("Magic Context checks passed: config merge, native modules, tools, commands, SQLite memory write/search (offline; no home activation)");
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
    ctx.shutdown();
  });
}
