// Run with BUN_BE_BUN=1 opencode2 scripts/check-opencode-latex.ts <plugin> [host-plugin].
import assert from "node:assert/strict"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { plugin } from "bun"

const packagePath = resolve(process.argv[2])
const hostPath = resolve(process.argv[3] ?? packagePath)
const load = (base: string, file: string) => import(pathToFileURL(`${base}/${file}`).href)
const { createTestRenderer, setRendererCapabilities } = await load(
  hostPath, "node_modules/@opentui/core/testing.bun.js",
)

// Share the host's runtime exports, as OpenCode does for external TUI plugins.
const { createRuntimePlugin } = await load(hostPath, "node_modules/@opentui/core/runtime-plugin.js")
await plugin(createRuntimePlugin({
  core: await load(hostPath, "node_modules/@opentui/core/index.bun.js"),
  additional: {
    "@opencode/plugin/tui": { Plugin: { define: (definition: unknown) => definition } },
  },
}))
const { default: tui } = await load(packagePath, "src/tui.ts")
const errors: string[] = []
const originalError = console.error
console.error = (...args) => {
  errors.push(args.map(String).join(" "))
  originalError(...args)
}

const formulas = [
  String.raw`\frac{a+b}{c}=\sqrt{a^2}`,
  String.raw`\int_{-\infty}^{\infty}e^{-x^2}\,dx=\sqrt{\pi}`,
  String.raw`\begin{aligned}x^2+6x+5&=0\\(x+3)^2&=4\\x&=-3\pm2\end{aligned}`,
  String.raw`A=\begin{pmatrix}1&2\\3&4\end{pmatrix}`,
]

for (const mode of ["cells", "kitty", "sixel", "auto-tmux"]) {
  const setup = await createTestRenderer({ width: 80, height: 24 })
  try {
    if (mode === "kitty" || mode === "auto-tmux") {
      setRendererCapabilities(setup.renderer, { multiplexer: "tmux" })
    } else if (mode === "sixel") {
      // Supply the pixel geometry normally reported by the terminal.
      setup.renderer._resolution = { width: 640, height: 384 }
      setRendererCapabilities(setup.renderer, { sixel: true, image_protocol: "sixel" })
    }

    let renderBlock: (token: { text: string }, render: object) => any
    tui.setup({
      renderer: setup.renderer,
      options: { graphicsMode: mode === "sixel" || mode === "auto-tmux" ? "auto" : mode },
      themeMode: "dark",
      storage: { store: () => [{ graphicsMode: null }, async () => {}] },
      keymap: { layer: () => {} },
      markdown: {
        registerCodeBlockRenderer(language: string, callback: typeof renderBlock) {
          assert.equal(language, "latex")
          renderBlock = callback
          return () => {}
        },
      },
    })
    const node = renderBlock!({ text: formulas[0] }, {
      defaultRender() { throw new Error("LaTeX constructor fell back to source") },
    })
    setup.renderer.root.add(node)

    for (const content of formulas) {
      node.content = content
      const graphics = await node.whenGraphicsReady()
      await setup.renderOnce()
      assert.equal(node.latexError, undefined)
      assert.equal(node.graphicsError, undefined)
      assert.equal(graphics, mode === "kitty" || mode === "sixel")
      assert(node.height > 0 && node.width === 80)
      if (!graphics) assert(!setup.captureCharFrame().includes("\\"))
    }
    setup.resize(36, 16)
    await setup.renderOnce()
    assert.equal(node.width, 36)
    assert(node.height > 0)
    console.log(`${mode}: renderer callback, four formulas, updates, paint and resize passed`)
  } finally {
    await setup.dispose()
  }
}
console.error = originalError
assert.deepEqual(errors, [], "Native painting or cleanup reported an error")
