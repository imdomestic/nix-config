import type { EngineInterface, Register } from 'claude-code'

import { decodedBytes, fitCells, hasImage, pngSize, readImage, splitImages } from './images'
import type { ImageSegment, MarkdownSegment } from './images'
import { hasMath, inlineToUnicode, splitDisplayMath, toUnicode } from './latex'

// Rex's cell at 2x; the terminal scales a picture to its cells anyway.
const CELL = { width: 18, height: 36 }
// The reply's bullet column, plus a margin.
const INDENT = 2
// A picture is drawn no taller than this many rows.
const MAX_ROWS = 16
// Bigger PNGs, and every other format, are redrawn at most this many pixels a side.
const THUMB_PX = 1000
const DIRECT_PNG_BYTES = 1_500_000

type Formula = { png: string; columns: number; rows: number } | { error: string }
type Job = { latex: string; color: string; maxColumns: number }
type Picture = { png: string; width: number; height: number } | { error: string }
type DisplaySegment = { kind: 'display'; latex: string }
type ReadPicture = NonNullable<ReturnType<typeof readImage>>

// The caches start empty on a reload and fill again.
const formulas = new Map<string, Formula>()
const formulasInFlight = new Map<string, Promise<void>>()
const pictures = new Map<string, Promise<Picture>>()
let color = '#c5c9c7'
let home = ''

const jobId = (job: Job) => `${job.color} ${job.maxColumns} ${job.latex}`
const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error))
const widthFor = (viewport: { columns: number } | undefined) =>
  Math.min(255, Math.max(8, (viewport?.columns ?? 100) - INDENT - 2))

// Renders every formula not yet drawn or under way in one node run, and
// waits for all of them. The main screen never draws a printed reply again,
// so a reply waits for its pictures rather than swapping them in later.
async function renderFormulas($: EngineInterface, jobs: Job[]) {
  const fresh = new Map<string, Job>()
  for (const job of jobs) {
    const id = jobId(job)
    if (!formulas.has(id) && !formulasInFlight.has(id)) fresh.set(id, job)
  }
  if (fresh.size > 0) {
    const run = runMathJax($, fresh)
    for (const id of fresh.keys()) formulasInFlight.set(id, run)
  }
  await Promise.all(jobs.map(job => formulasInFlight.get(jobId(job))))
}

// render.mjs runs on the node its shebang names; the package points it at
// one from the store.
async function runRenderer(
  $: EngineInterface,
  work: { formulas?: Array<Job & { id: string }>; pictures?: Array<{ id: string; path?: string; base64?: string }> },
) {
  const { exitCode, stdout, stderr } = await $.process.run([`${$.plugin.root}/render/render.mjs`], {
    stdin: JSON.stringify({ cellWidthPx: CELL.width, cellHeightPx: CELL.height, thumbPx: THUMB_PX, ...work }),
    timeoutMs: 20_000,
  })
  if (exitCode !== 0) throw new Error(stderr.trim().split('\n').pop() || `render.mjs exited ${exitCode}`)
  return JSON.parse(stdout) as { formulas: Record<string, Formula>; pictures: Record<string, Picture> }
}

async function runMathJax($: EngineInterface, batch: Map<string, Job>) {
  try {
    const results = (await runRenderer($, { formulas: [...batch].map(([id, job]) => ({ id, ...job })) })).formulas
    for (const id of batch.keys()) formulas.set(id, results[id] ?? { error: 'no result' })
  } catch (error) {
    for (const id of batch.keys()) formulas.set(id, { error: errorText(error) })
  } finally {
    for (const id of batch.keys()) formulasInFlight.delete(id)
  }
}

// A PNG of a PNG, JPEG, GIF or SVG image, from a file or from base64.
async function thumbnail($: EngineInterface, from: { path: string } | { base64: string }): Promise<Picture> {
  return (await runRenderer($, { pictures: [{ id: 'one', ...from }] })).pictures.one ?? { error: 'no result' }
}

function picture(key: string, load: () => Promise<Picture>): Promise<Picture> {
  let pending = pictures.get(key)
  if (pending === undefined) {
    pending = load().catch(error => ({ error: errorText(error) }))
    pictures.set(key, pending)
  }
  return pending
}

function readPicture($: EngineInterface, key: string, image: ReadPicture) {
  return picture(key, async () => {
    const size = image.mediaType === 'image/png' ? pngSize(image.base64) : undefined
    if (size && decodedBytes(image.base64) <= DIRECT_PNG_BYTES) return { png: image.base64, ...size }
    return thumbnail($, { base64: image.base64 })
  })
}

function filePicture($: EngineInterface, path: string) {
  const full = path.startsWith('~/') ? `${home}${path.slice(1)}` : path
  return picture(`file ${full}`, async () => {
    if (/\.png$/i.test(full)) {
      const { base64 } = await $.fs.read(full, { as: 'bytes' })
      const size = pngSize(base64)
      if (size && decodedBytes(base64) <= DIRECT_PNG_BYTES) return { png: base64, ...size }
    }
    return thumbnail($, { path: full })
  })
}

// Pasted pictures: a user row's image blocks, matched to the row the
// transcript draws by its text. Kept as each prompt is appended, and read
// back from the conversation for rows from before a reload or a --continue.
type Pasted = { base64: string; mediaType: string }
let pastedByText = new Map<string, Pasted[]>()
let indexing: Promise<void> | undefined
let indexedAt = 0

const pasteKey = (text: string) =>
  text.replace(/\[Image: source: [^\]]*\]/g, '').replace(/\s+/g, ' ').trim()

function imageBlock(block: { type: string; [field: string]: unknown }): Pasted[] {
  const source = block.source as { type?: unknown; data?: unknown; media_type?: unknown } | undefined
  return block.type === 'image' && source?.type === 'base64' && typeof source.data === 'string'
    ? [{ base64: source.data, mediaType: typeof source.media_type === 'string' ? source.media_type : 'image/png' }]
    : []
}

// Whether the row carried pictures. A request merges reminders into the
// prompt's message as text blocks, so each block is a key of its own.
function indexRow(content: ReadonlyArray<{ type: string; [field: string]: unknown }>): boolean {
  const images = content.flatMap(imageBlock)
  if (images.length === 0) return false
  const text = content.flatMap(block =>
    block.type === 'text' && typeof block.text === 'string' && !block.text.startsWith('<system-reminder>')
      ? [pasteKey(block.text)]
      : [],
  )
  for (const key of [...text, text.join(' ')]) if (key !== '') pastedByText.set(key, images)
  return true
}

async function indexPasted($: EngineInterface) {
  for (const message of await $.session.messages({ as: 'api' })) {
    if (message.role === 'user') indexRow(message.content)
  }
}

async function pastedFor($: EngineInterface, text: string, now: number): Promise<Pasted[]> {
  const key = pasteKey(text)
  const known = pastedByText.get(key)
  if (known !== undefined) return known
  // A row typed as "[Image #1]" with no picture would rescan on every draw.
  if (indexing === undefined && now - indexedAt > 2000) {
    indexedAt = now
    indexing = indexPasted($).finally(() => {
      indexing = undefined
    })
  }
  await indexing
  return pastedByText.get(key) ?? []
}

function filePathOf(input: unknown): string {
  const path = typeof input === 'object' && input !== null ? (input as { file_path?: unknown }).file_path : undefined
  return typeof path === 'string' ? path : 'image'
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    const theme = (await $.config.list()).find(row => row.key === 'theme')?.value
    // Kanso Pearl's and Kanso Zen's foregrounds, the themes Rex uses here.
    color = String(theme ?? '').includes('light') ? '#22262d' : '#c5c9c7'
    home = (await $.env.get('HOME')) ?? ''
    return next(e)
  })

  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    const text = e.props.text
    if (e.surface !== 'terminal' || !(hasMath(text) || hasImage(text))) return next(e)

    const segments = splitDisplayMath(text).flatMap<MarkdownSegment | ImageSegment | DisplaySegment>(segment =>
      segment.kind === 'markdown' ? splitImages(segment.text) : [segment],
    )
    if (segments.every(segment => segment.kind === 'markdown')) {
      const rewritten = inlineToUnicode(text)
      return rewritten === text ? next(e) : next({ ...e, props: { ...e.props, text: rewritten } })
    }

    const maxColumns = widthFor(e.viewport)
    const jobOf = (latex: string): Job => ({ latex, color, maxColumns })
    const files = new Map<string, Promise<Picture>>()
    for (const segment of segments) {
      if (segment.kind === 'image') files.set(segment.path, filePicture($, segment.path))
    }
    await renderFormulas($, segments.flatMap(segment => (segment.kind === 'display' ? [jobOf(segment.latex)] : [])))
    const loaded = new Map<string, Picture>()
    for (const [path, pending] of files) loaded.set(path, await pending)

    const { Box, Text, Markdown, Image } = $.ui.resolve(e)
    // The engine draws the first markdown part, bullet and all; the rest
    // goes under it at the bullet's indent.
    const first = segments[0]?.kind === 'markdown' ? segments.shift() : undefined
    const headText = first?.kind === 'markdown' ? inlineToUnicode(first.text).trim() : ''
    const head = await next({ ...e, props: { ...e.props, text: headText || ' ' } })

    const body = segments.map((segment, index) => {
      if (segment.kind === 'markdown') {
        const part = inlineToUnicode(segment.text).trim()
        return part ? (
          <Box marginTop={1}>
            <Markdown key={`md-${index}`} text={part} />
          </Box>
        ) : null
      }
      if (segment.kind === 'image') {
        const shown = loaded.get(segment.path)
        const alt = segment.alt || segment.path
        if (shown === undefined || 'error' in shown) {
          return (
            <Box marginTop={1}>
              <Text dimColor>
                [{alt}] inline-media: {shown && 'error' in shown ? shown.error : 'not loaded'}
              </Text>
            </Box>
          )
        }
        const cells = fitCells(shown.width, shown.height, CELL, maxColumns, MAX_ROWS)
        return (
          <Box marginTop={1}>
            <Image source={{ png: shown.png }} columns={cells.columns} rows={cells.rows} alt={alt} />
          </Box>
        )
      }
      const formula = formulas.get(jobId(jobOf(segment.latex)))
      const alt = toUnicode(segment.latex) || ' '
      if (formula === undefined || 'error' in formula) {
        return (
          <Box marginTop={1} flexDirection="column">
            <Text>{alt}</Text>
            {formula && <Text dimColor>inline-media: {formula.error}</Text>}
          </Box>
        )
      }
      return (
        <Box marginTop={1}>
          <Image source={{ png: formula.png }} columns={formula.columns} rows={formula.rows} alt={alt} />
        </Box>
      )
    })

    return (
      <Box flexDirection="column">
        {head}
        <Box flexDirection="column" paddingLeft={INDENT}>
          {body}
        </Box>
      </Box>
    )
  })

  // A picture Read returned goes under the row reporting the call: the
  // collapsed group ("Read 1 file") here, the call's own row when expanded.
  on('ui.render', { component: 'ToolGroup' }, async ($, e, next) => {
    if (e.surface !== 'terminal' || e.props.isExpanded) return next(e)
    const shots = e.props.calls.flatMap((call, index) => {
      const image = call.isRunning || call.isErrored ? undefined : readImage(call.tool, call.output)
      return image === undefined
        ? []
        : [{ key: call.tool_use_id ?? `${e.requestId} ${index}`, image, path: filePathOf(call.input) }]
    })
    if (shots.length === 0) return next(e)

    const head = await next(e)
    const shown = await Promise.all(shots.map(shot => readPicture($, shot.key, shot.image)))
    const maxColumns = widthFor(e.viewport)
    const { Box, Text, Image } = $.ui.resolve(e)
    return (
      <Box flexDirection="column">
        {head}
        <Box flexDirection="column" paddingLeft={INDENT}>
          {shots.map((shot, index) => {
            const one = shown[index]
            if (one === undefined || 'error' in one) {
              return <Text dimColor>inline-media: {one && 'error' in one ? one.error : 'no picture'}</Text>
            }
            const cells = fitCells(one.width, one.height, CELL, maxColumns, MAX_ROWS)
            return <Image source={{ png: one.png }} columns={cells.columns} rows={cells.rows} alt={shot.path} />
          })}
        </Box>
      </Box>
    )
  })

  // A prompt row is drawn before it is stored, so its first draw finds no
  // pictures: keep them as the row is appended, then draw the rows again.
  on('session.append', { door: 'prompt' }, async ($, e, next) => {
    const stored = await next(e)
    if (e.agentId === undefined && indexRow(e.message.content)) $.ui.invalidate('ui.render')
    return stored
  })

  // A prompt holding "[Image #N]" draws the pictures it carried under it.
  on('ui.render', { component: 'UserMessage' }, async ($, e, next) => {
    if (e.surface !== 'terminal' || !e.props.text.includes('[Image #')) return next(e)
    const pasted = await pastedFor($, e.props.text, await $.clock.now())
    if (pasted.length === 0) return next(e)

    const head = await next(e)
    const shown = await Promise.all(
      pasted.map((image, index) => readPicture($, `paste ${e.requestId} ${index}`, image)),
    )
    const numbers = [...e.props.text.matchAll(/\[Image #(\d+)\]/g)].map(match => match[1])
    const maxColumns = widthFor(e.viewport)
    const { Box, Text, Image } = $.ui.resolve(e)
    return (
      <Box flexDirection="column">
        {head}
        <Box flexDirection="column" paddingLeft={INDENT}>
          {shown.map((one, index) => {
            if ('error' in one) return <Text dimColor>inline-media: {one.error}</Text>
            const cells = fitCells(one.width, one.height, CELL, maxColumns, MAX_ROWS)
            const alt = `Image #${numbers[index] ?? index + 1}`
            return <Image source={{ png: one.png }} columns={cells.columns} rows={cells.rows} alt={alt} />
          })}
        </Box>
      </Box>
    )
  })

  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    const image = e.props.isRunning || e.props.isErrored ? undefined : readImage(e.props.tool, e.props.output)
    if (e.surface !== 'terminal' || image === undefined) return next(e)

    const head = await next(e)
    const one = await readPicture($, e.props.tool_use_id, image)
    const { Box, Text, Image } = $.ui.resolve(e)
    const cells = 'error' in one ? undefined : fitCells(one.width, one.height, CELL, widthFor(e.viewport), MAX_ROWS)
    return (
      <Box flexDirection="column">
        {head}
        <Box paddingLeft={INDENT}>
          {'error' in one || cells === undefined ? (
            <Text dimColor>inline-media: {'error' in one ? one.error : 'no picture'}</Text>
          ) : (
            <Image source={{ png: one.png }} columns={cells.columns} rows={cells.rows} alt={filePathOf(e.props.input)} />
          )}
        </Box>
      </Box>
    )
  })
}
