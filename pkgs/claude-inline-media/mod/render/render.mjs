#!/usr/bin/env node
// Draws PNGs for the inline-media mod: display formulas, and pictures shrunk
// for the terminal.
//
// stdin:  { cellWidthPx, cellHeightPx, thumbPx,
//           formulas?: [{ id, latex, color, maxColumns }],
//           pictures?: [{ id, path } | { id, base64 }] }
// stdout: { formulas: { [id]: { png, columns, rows } | { error } },
//           pictures: { [id]: { png, width, height } | { error } } }
//
// mathjax-full and @resvg/resvg-js come from the node_modules next to this
// file (the package links pi-math's there), or from NODE_PATH.
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

// One ex of the formula is half a cell's height, as pi-math sizes it.
const EX_TO_ROWS = 0.5

const input = JSON.parse(readFileSync(0, 'utf8'))
const require = createRequire(import.meta.url)
const { Resvg } = require('@resvg/resvg-js')

const cellW = input.cellWidthPx
const cellH = input.cellHeightPx

// Loading MathJax takes a while; a run with pictures alone skips it.
let math
function mathJax() {
  if (math !== undefined) return math
  const { mathjax } = require('mathjax-full/js/mathjax.js')
  const { TeX } = require('mathjax-full/js/input/tex.js')
  const { SVG } = require('mathjax-full/js/output/svg.js')
  const { liteAdaptor } = require('mathjax-full/js/adaptors/liteAdaptor.js')
  const { RegisterHTMLHandler } = require('mathjax-full/js/handlers/html.js')
  const { AllPackages } = require('mathjax-full/js/input/tex/AllPackages.js')
  const adaptor = liteAdaptor()
  RegisterHTMLHandler(adaptor)
  const doc = mathjax.document('', {
    InputJax: new TeX({
      packages: AllPackages,
      // MathJax draws a red error box by default; the mod shows the source instead.
      formatError: (_jax, error) => {
        throw error
      },
    }),
    OutputJax: new SVG({ fontCache: 'none' }),
  })
  math = { adaptor, doc }
  return math
}

function exAttr(svg, name) {
  const match = new RegExp(`\\b${name}="([\\d.]+)ex"`).exec(svg)
  return match ? Number.parseFloat(match[1]) : undefined
}

function formula({ latex, color, maxColumns }) {
  const { adaptor, doc } = mathJax()
  const html = adaptor.outerHTML(doc.convert(latex, { display: true }))
  const svg = html.slice(html.indexOf('<svg'), html.lastIndexOf('</svg>') + 6)
  const widthEx = exAttr(svg, 'width')
  const heightEx = exAttr(svg, 'height')
  if (!widthEx || !heightEx) throw new Error('MathJax gave no size')

  const naturalRows = heightEx * EX_TO_ROWS
  const naturalCols = (naturalRows * widthEx * cellH) / (heightEx * cellW)
  const scale = Math.min(1, maxColumns / naturalCols)
  const columns = Math.max(1, Math.ceil(naturalCols * scale))
  const rows = Math.max(1, Math.ceil(naturalRows * scale))
  const canvasW = columns * cellW
  const canvasH = rows * cellH
  const contentW = naturalCols * scale * cellW
  const contentH = naturalRows * scale * cellH

  const open = svg.slice(0, svg.indexOf('>') + 1)
  const viewBox = /viewBox="([^"]+)"/.exec(open)?.[1]
  const body = svg.slice(open.length, -6)
  const page = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${canvasW}" height="${canvasH}" color="${color}">`,
    `<svg x="0" y="${(canvasH - contentH) / 2}" width="${contentW}" height="${contentH}" viewBox="${viewBox}" overflow="visible">`,
    body,
    '</svg></svg>',
  ].join('')
  // MathJax draws Latin text as paths; only other scripts (\text{中文}) need
  // system fonts, and scanning them costs over a second.
  const loadSystemFonts = /[^\x00-\x7f]/.test(latex)
  const png = new Resvg(page, { font: { loadSystemFonts } }).render().asPng()
  return { png: png.toString('base64'), columns, rows }
}

function rasterType(bytes) {
  const head = bytes.subarray(0, 12)
  if (head.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) return 'image/png'
  if (head.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) return 'image/jpeg'
  if (head.toString('latin1', 0, 4) === 'GIF8') return 'image/gif'
  if (head.toString('latin1', 0, 4) === 'RIFF' && head.toString('latin1', 8, 12) === 'WEBP') return 'image/webp'
  return undefined
}

// A raster picture goes into an SVG of its own size, which resvg decodes.
function picture({ path, base64 }) {
  const bytes = path !== undefined ? readFileSync(path) : Buffer.from(base64, 'base64')
  const type = rasterType(bytes)
  const isSvg = type === undefined && /^\s*(<\?xml[^>]*>\s*)?(<!--[\s\S]*?-->\s*|<!DOCTYPE[^>]*>\s*)*<svg[\s>]/i.test(bytes.toString('utf8', 0, 4096))
  if (type === undefined && !isSvg) throw new Error('not a PNG, JPEG, GIF, WebP or SVG image')
  const svg = isSvg
    ? bytes
    : `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:${type};base64,${bytes.toString('base64')}"/></svg>`
  // Drawings are made for paper: give them its white, and fonts for their text.
  const options = isSvg ? { background: 'white', font: { loadSystemFonts: true } } : { font: { loadSystemFonts: false } }
  const probe = new Resvg(svg, options)
  // An image resvg cannot decode is dropped, leaving nothing to draw.
  if (probe.getBBox() === undefined) throw new Error(`could not decode the ${type ?? 'SVG'}`)
  const scale = Math.min(1, input.thumbPx / Math.max(probe.width, probe.height))
  const width = Math.max(1, Math.round(probe.width * scale))
  const shown = scale < 1 ? new Resvg(svg, { ...options, fitTo: { mode: 'width', value: width } }) : probe
  const image = shown.render()
  return { png: image.asPng().toString('base64'), width: image.width, height: image.height }
}

function each(items, draw) {
  const results = {}
  for (const item of items ?? []) {
    try {
      results[item.id] = draw(item)
    } catch (error) {
      // MathJax's TexError is no Error subclass, but it has a message.
      results[item.id] = { error: String(error?.message ?? error) }
    }
  }
  return results
}

process.stdout.write(JSON.stringify({ formulas: each(input.formulas, formula), pictures: each(input.pictures, picture) }))
