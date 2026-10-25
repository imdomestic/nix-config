// Pictures in the transcript: where they come from, and how many cells they take.

export type ImageSegment = { kind: 'image'; alt: string; path: string }
export type MarkdownSegment = { kind: 'markdown'; text: string }

const FENCE = /^\s*(`{3,}|~{3,})/
// A line holding one local image and nothing else: ![alt](path "title")
const BLOCK_IMAGE = /^\s*!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)\s*$/

// Splits out image lines; a remote picture, or one inside a code fence, stays text.
export function splitImages(markdown: string): Array<MarkdownSegment | ImageSegment> {
  const segments: Array<MarkdownSegment | ImageSegment> = []
  let lines: string[] = []
  let fence: string | undefined
  const flush = () => {
    if (lines.length > 0) segments.push({ kind: 'markdown', text: lines.join('\n') })
    lines = []
  }
  for (const line of markdown.split('\n')) {
    const marker = FENCE.exec(line)?.[1]
    if (fence !== undefined) {
      if (marker !== undefined && marker[0] === fence[0] && marker.length >= fence.length) {
        fence = undefined
      }
      lines.push(line)
      continue
    }
    if (marker !== undefined) {
      fence = marker
      lines.push(line)
      continue
    }
    const image = BLOCK_IMAGE.exec(line)
    const path = image?.[2]
    if (image === null || path === undefined || /^[a-z][a-z0-9+.-]*:\/\//i.test(path)) {
      lines.push(line)
      continue
    }
    flush()
    segments.push({ kind: 'image', alt: image[1] ?? '', path: decodeURI(path.replace(/^file:\/\//, '')) })
  }
  flush()
  return segments
}

export function hasImage(text: string): boolean {
  return text.includes('![')
}

// A PNG's width and height from its IHDR chunk, read from the base64.
export function pngSize(base64: string): { width: number; height: number } | undefined {
  try {
    const head = atob(base64.slice(0, 32))
    if (!head.startsWith('\x89PNG') || head.slice(12, 16) !== 'IHDR') return undefined
    const word = (at: number) =>
      ((head.charCodeAt(at) << 24) | (head.charCodeAt(at + 1) << 16) | (head.charCodeAt(at + 2) << 8) | head.charCodeAt(at + 3)) >>> 0
    const width = word(16)
    const height = word(20)
    return width > 0 && height > 0 ? { width, height } : undefined
  } catch {
    return undefined
  }
}

export function decodedBytes(base64: string): number {
  return Math.floor((base64.length * 3) / 4)
}

// The cells a picture of width x height pixels fills, its shape kept, no
// taller than maxRows, no wider than maxColumns, never blown up past its
// own pixels.
export function fitCells(
  width: number,
  height: number,
  cell: { width: number; height: number },
  maxColumns: number,
  maxRows: number,
): { columns: number; rows: number } {
  let rows = Math.min(maxRows, Math.max(1, Math.ceil(height / cell.height)))
  let columns = Math.max(1, Math.round((rows * cell.height * width) / (height * cell.width)))
  if (columns > maxColumns) {
    columns = maxColumns
    rows = Math.max(1, Math.round((columns * cell.width * height) / (width * cell.height)))
  }
  return { columns: Math.min(255, columns), rows: Math.min(255, rows) }
}

// The picture a Read call's output carries, when it read an image.
export function readImage(
  tool: string,
  output: unknown,
): { base64: string; mediaType: string; width?: number; height?: number } | undefined {
  if (tool !== 'Read' || typeof output !== 'object' || output === null) return undefined
  const record = output as { type?: unknown; file?: { base64?: unknown; type?: unknown; dimensions?: Record<string, unknown> } }
  const file = record.file
  if (record.type !== 'image' || typeof file?.base64 !== 'string') return undefined
  const dimensions = file.dimensions ?? {}
  const number = (value: unknown) => (typeof value === 'number' && value > 0 ? value : undefined)
  return {
    base64: file.base64,
    mediaType: typeof file.type === 'string' ? file.type : 'image/png',
    width: number(dimensions.displayWidth) ?? number(dimensions.originalWidth),
    height: number(dimensions.displayHeight) ?? number(dimensions.originalHeight),
  }
}
