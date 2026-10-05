import assert from "node:assert/strict"
import { readFileSync, writeFileSync } from "node:fs"
import { resolve } from "node:path"

const [configPath, model, outputPath] = process.argv.slice(2)
assert(configPath && model && outputPath, "Usage: bun scripts/verify-bonsai-prefill.ts CONFIG MODEL OUTPUT.json")
const config = JSON.parse(readFileSync(configPath, "utf8"))
const plugin = config.plugin.find((entry: unknown) => Array.isArray(entry) && entry[1]?.prefillWsEndpoints?.length)
assert(plugin, "Missing authenticated prefill plugin configuration")
const { readPrefillEndpoints, connectPrefillSocket } = await import(`${plugin[0]}/src/prefill-endpoints.ts`)
const endpoints = readPrefillEndpoints(plugin[1].prefillWsEndpoints)
const provider = config.provider["local-bonsai"]
assert(provider, "Missing local-bonsai provider")
const endpoint = plugin[1].prefillWsEndpoints[0]
const headers = endpoints.get(endpoint.url)
assert(headers, "Missing endpoint authentication")
const sessionID = `prefill-verification-${crypto.randomUUID()}`
const messageID = `message-${crypto.randomUUID()}`
const events: Record<string, any>[] = []
const socket = connectPrefillSocket(endpoint.url, endpoints)
socket.addEventListener("message", (event: MessageEvent) => {
  const data = JSON.parse(String(event.data))
  if (data.session_id === sessionID) events.push(data)
})
await new Promise<void>((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("WebSocket connection timed out")), 10000)
  socket.addEventListener("open", () => { clearTimeout(timer); resolve() }, { once: true })
  socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("WebSocket connection failed")) }, { once: true })
})

try {
  const unauthenticated = await fetch(endpoint.url.replace(/^ws/, "http"), { signal: AbortSignal.timeout(10000) })
  assert.equal(unauthenticated.status, 401, "Progress endpoint must require authentication")
  const source = ["AGENTS.md", "README.md", "docs/incidents.md"]
    .map(path => `${path}\n${readFileSync(resolve(path), "utf8")}`).join("\n\n")
  const started = performance.now()
  const response = await fetch(`${provider.options.baseURL}/chat/completions`, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json", "x-opencode-session-id": sessionID, "x-opencode-message-id": messageID },
    body: JSON.stringify({
      model, stream: true, max_tokens: 128, reasoning_effort: "low",
      messages: [{ role: "user", content: `请阅读以下真实仓库文档，用一句中文说明仓库管理哪些配置。\n${source}` }],
    }),
    signal: AbortSignal.timeout(300000),
  })
  assert.equal(response.status, 200, `Inference returned HTTP ${response.status}`)
  const responseBytes = (await response.arrayBuffer()).byteLength
  await Bun.sleep(200)
  const elapsedSeconds = (performance.now() - started) / 1000
  const progress = events.filter(event => event.processed > event.cache && event.time_ms > 0)
  const timing = events.find(event => event.timings?.predicted_per_second > 0)
  const result = {
    model, sessionID, responseBytes, elapsedSeconds, authenticated: true, unauthenticatedStatus: unauthenticated.status,
    progressEvents: progress.length, finalProgress: progress.at(-1), timing, events,
  }
  writeFileSync(outputPath, JSON.stringify(result, null, 2) + "\n")
  assert(progress.length > 1, "No live prefill progress received")
  assert(events.some(event => event.done), "No prefill completion received")
  assert(timing, "No backend generation speed received")
  console.log(JSON.stringify({ model, elapsedSeconds, progressEvents: progress.length, finalProgress: progress.at(-1), timing }, null, 2))
} finally {
  socket.close()
}
