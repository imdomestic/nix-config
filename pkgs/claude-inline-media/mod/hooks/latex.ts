// Finding math in a reply's markdown, and LaTeX to Unicode for inline math.

export type Segment = { kind: 'markdown'; text: string } | { kind: 'display'; latex: string }

const FENCE = /^\s*(`{3,}|~{3,})/

// Follows fenced code blocks line by line: true for a line inside one,
// its opening and closing fences included.
function fenceTracker(): (line: string) => boolean {
  let fence: string | undefined
  return line => {
    const marker = FENCE.exec(line)?.[1]
    if (fence !== undefined) {
      if (marker !== undefined && marker[0] === fence[0] && marker.length >= fence.length) {
        fence = undefined
      }
      return true
    }
    fence = marker
    return marker !== undefined
  }
}

// Display math is a block on lines of its own: $$ ... $$ or \[ ... \].
// Anything inside a fenced code block is left alone.
export function splitDisplayMath(text: string): Segment[] {
  const lines = text.split('\n')
  const isCode = fenceTracker()
  const segments: Segment[] = []
  let markdown: string[] = []

  const flush = () => {
    if (markdown.length > 0) segments.push({ kind: 'markdown', text: markdown.join('\n') })
    markdown = []
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? ''
    const trimmed = line.trim()
    const opener = trimmed.startsWith('$$') ? '$$' : trimmed.startsWith('\\[') ? '\\[' : undefined
    if (isCode(line) || opener === undefined) {
      markdown.push(line)
      continue
    }
    const closer = opener === '$$' ? '$$' : '\\]'
    const rest = trimmed.slice(2)
    // Closed on the same line: $$ x $$, and nothing after it.
    if (rest.endsWith(closer)) {
      const latex = rest.slice(0, -2).trim()
      if (latex.length > 0 && !latex.includes(closer)) {
        flush()
        segments.push({ kind: 'display', latex })
        continue
      }
    }
    // Opened here, closed on a later line ending with the closer.
    const end = lines.findIndex((later, j) => j > i && later.trimEnd().endsWith(closer))
    const body =
      end === -1
        ? ''
        : [rest, ...lines.slice(i + 1, end), (lines[end] ?? '').trimEnd().slice(0, -2)].join('\n').trim()
    if (body.length === 0) {
      markdown.push(line)
      continue
    }
    flush()
    segments.push({ kind: 'display', latex: body })
    i = end
  }
  flush()
  return segments
}

// $x$ with no space just inside either dollar and no digit after the closing
// one (so "$5 and $10" stays), or \( x \).
const INLINE = /(?<![\\$])\$(?![\s$])((?:\\\$|[^$\n])+?)(?<![\s\\])\$(?![\d$])|\\\((.+?)\\\)/g
// A $...$ that reads as prose ($PATH:$HOME) has none of these.
const MATHY = /[\\^_{}=+<>|0-9]|^[A-Za-z]{1,2}$/

export function hasMath(text: string): boolean {
  return /\$|\\\(|\\\[/.test(text)
}

// Rewrites inline math outside code spans and fences as Unicode.
export function inlineToUnicode(markdown: string): string {
  const isCode = fenceTracker()
  return markdown
    .split('\n')
    .map(line =>
      isCode(line)
        ? line
        : // Odd pieces of a split on backtick runs are code spans.
          line
            .split(/(`+[^`]*`+)/)
            .map((part, index) =>
              index % 2 === 1
                ? part
                : part.replace(INLINE, (whole, dollar?: string, paren?: string) => {
                    const latex = dollar ?? paren ?? ''
                    if (dollar !== undefined && !MATHY.test(latex)) return whole
                    return escapeMarkdown(toUnicode(latex))
                  }),
            )
            .join(''),
    )
    .join('\n')
}

function escapeMarkdown(text: string): string {
  return text.replace(/([*_`[\]\\])/g, '\\$1')
}

const SYMBOLS: Record<string, string> = {
  alpha: 'α', beta: 'β', gamma: 'γ', delta: 'δ', epsilon: 'ϵ', varepsilon: 'ε',
  zeta: 'ζ', eta: 'η', theta: 'θ', vartheta: 'ϑ', iota: 'ι', kappa: 'κ',
  lambda: 'λ', mu: 'μ', nu: 'ν', xi: 'ξ', pi: 'π', varpi: 'ϖ', rho: 'ρ',
  varrho: 'ϱ', sigma: 'σ', varsigma: 'ς', tau: 'τ', upsilon: 'υ', phi: 'ϕ',
  varphi: 'φ', chi: 'χ', psi: 'ψ', omega: 'ω',
  Gamma: 'Γ', Delta: 'Δ', Theta: 'Θ', Lambda: 'Λ', Xi: 'Ξ', Pi: 'Π',
  Sigma: 'Σ', Upsilon: 'Υ', Phi: 'Φ', Psi: 'Ψ', Omega: 'Ω',
  cdot: '·', times: '×', div: '÷', pm: '±', mp: '∓', ast: '∗', star: '⋆',
  circ: '∘', bullet: '•', oplus: '⊕', otimes: '⊗',
  leq: '≤', le: '≤', geq: '≥', ge: '≥', neq: '≠', ne: '≠', approx: '≈',
  equiv: '≡', sim: '∼', simeq: '≃', cong: '≅', propto: '∝', ll: '≪', gg: '≫',
  infty: '∞', partial: '∂', nabla: '∇', sum: '∑', prod: '∏', coprod: '∐',
  int: '∫', iint: '∬', iiint: '∭', oint: '∮', sqrt: '√',
  in: '∈', notin: '∉', ni: '∋', subset: '⊂', subseteq: '⊆', supset: '⊃',
  supseteq: '⊇', cup: '∪', cap: '∩', setminus: '∖', emptyset: '∅',
  varnothing: '∅', forall: '∀', exists: '∃', nexists: '∄', neg: '¬', lnot: '¬',
  land: '∧', wedge: '∧', lor: '∨', vee: '∨',
  to: '→', rightarrow: '→', leftarrow: '←', gets: '←', leftrightarrow: '↔',
  Rightarrow: '⇒', implies: '⇒', Leftarrow: '⇐', Leftrightarrow: '⇔',
  iff: '⇔', mapsto: '↦', uparrow: '↑', downarrow: '↓', longrightarrow: '⟶',
  ldots: '…', dots: '…', cdots: '⋯', vdots: '⋮', ddots: '⋱',
  perp: '⊥', parallel: '∥', mid: '∣', angle: '∠', triangle: '△',
  prime: '′', degree: '°', hbar: 'ℏ', ell: 'ℓ', Re: 'ℜ', Im: 'ℑ', aleph: 'ℵ',
  langle: '⟨', rangle: '⟩', lfloor: '⌊', rfloor: '⌋', lceil: '⌈', rceil: '⌉',
  vert: '|', Vert: '‖', lvert: '|', rvert: '|', lVert: '‖', rVert: '‖',
  top: '⊤', bot: '⊥', vdash: '⊢', models: '⊨', square: '□', checkmark: '✓',
  quad: '  ', qquad: '    ', ',': ' ', ':': ' ', ';': ' ', '>': ' ', '!': '',
  ' ': ' ', '{': '{', '}': '}', '%': '%', '$': '$', '#': '#', '&': '&', '_': '_',
  '|': '‖', lbrace: '{', rbrace: '}', backslash: '\\',
  sin: 'sin', cos: 'cos', tan: 'tan', cot: 'cot', sec: 'sec', csc: 'csc',
  arcsin: 'arcsin', arccos: 'arccos', arctan: 'arctan', sinh: 'sinh',
  cosh: 'cosh', tanh: 'tanh', log: 'log', ln: 'ln', lg: 'lg', exp: 'exp',
  lim: 'lim', limsup: 'lim sup', liminf: 'lim inf', max: 'max', min: 'min',
  sup: 'sup', inf: 'inf', arg: 'arg', det: 'det', dim: 'dim', ker: 'ker',
  deg: 'deg', gcd: 'gcd', Pr: 'Pr', mod: 'mod', bmod: 'mod',
}

// Sizing and spacing commands that print nothing.
const DROPPED = new Set([
  'left', 'right', 'big', 'Big', 'bigg', 'Bigg', 'bigl', 'bigr', 'Bigl', 'Bigr',
  'biggl', 'biggr', 'displaystyle', 'textstyle', 'scriptstyle', 'limits',
  'nolimits', 'middle',
])

const COMBINING: Record<string, string> = {
  hat: '̂', widehat: '̂', tilde: '̃', widetilde: '̃',
  bar: '̄', overline: '̅', vec: '⃗', dot: '̇',
  ddot: '̈', check: '̌', breve: '̆', acute: '́',
  grave: '̀', underline: '̲',
}
const WIDE = new Set(['overline', 'underline', 'bar', 'widehat', 'widetilde'])

const SUPER: Record<string, string> = {
  '0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶',
  '7': '⁷', '8': '⁸', '9': '⁹', '+': '⁺', '-': '⁻', '−': '⁻', '=': '⁼',
  '(': '⁽', ')': '⁾', a: 'ᵃ', b: 'ᵇ', c: 'ᶜ', d: 'ᵈ', e: 'ᵉ', f: 'ᶠ',
  g: 'ᵍ', h: 'ʰ', i: 'ⁱ', j: 'ʲ', k: 'ᵏ', l: 'ˡ', m: 'ᵐ', n: 'ⁿ', o: 'ᵒ',
  p: 'ᵖ', r: 'ʳ', s: 'ˢ', t: 'ᵗ', u: 'ᵘ', v: 'ᵛ', w: 'ʷ', x: 'ˣ', y: 'ʸ',
  z: 'ᶻ', A: 'ᴬ', B: 'ᴮ', D: 'ᴰ', E: 'ᴱ', G: 'ᴳ', H: 'ᴴ', I: 'ᴵ', J: 'ᴶ',
  K: 'ᴷ', L: 'ᴸ', M: 'ᴹ', N: 'ᴺ', O: 'ᴼ', P: 'ᴾ', R: 'ᴿ', T: 'ᵀ', U: 'ᵁ',
  V: 'ⱽ', W: 'ᵂ', '′': '′', '*': '*', 'α': 'ᵅ', 'β': 'ᵝ', 'γ': 'ᵞ',
  'δ': 'ᵟ', 'θ': 'ᶿ', 'φ': 'ᵠ', 'χ': 'ᵡ', ' ': ' ',
}

const SUB: Record<string, string> = {
  '0': '₀', '1': '₁', '2': '₂', '3': '₃', '4': '₄', '5': '₅', '6': '₆',
  '7': '₇', '8': '₈', '9': '₉', '+': '₊', '-': '₋', '−': '₋', '=': '₌',
  '(': '₍', ')': '₎', a: 'ₐ', e: 'ₑ', h: 'ₕ', i: 'ᵢ', j: 'ⱼ', k: 'ₖ',
  l: 'ₗ', m: 'ₘ', n: 'ₙ', o: 'ₒ', p: 'ₚ', r: 'ᵣ', s: 'ₛ', t: 'ₜ', u: 'ᵤ',
  v: 'ᵥ', x: 'ₓ', 'β': 'ᵦ', 'γ': 'ᵧ', 'ρ': 'ᵨ', 'φ': 'ᵩ', 'χ': 'ᵪ', ' ': ' ',
}

function alphabet(start: number, exceptions: Record<string, string> = {}) {
  return (char: string) => {
    if (exceptions[char]) return exceptions[char]
    const code = char.codePointAt(0) ?? 0
    if (code >= 65 && code <= 90) return String.fromCodePoint(start + code - 65)
    if (code >= 97 && code <= 122) return String.fromCodePoint(start + 26 + code - 97)
    return char
  }
}

const FONTS: Record<string, (char: string) => string> = {
  mathbb: alphabet(0x1d538, {
    C: 'ℂ', H: 'ℍ', N: 'ℕ', P: 'ℙ', Q: 'ℚ', R: 'ℝ', Z: 'ℤ',
    '0': '𝟘', '1': '𝟙', '2': '𝟚',
  }),
  mathcal: alphabet(0x1d4d0),
  mathscr: alphabet(0x1d4d0),
  mathfrak: alphabet(0x1d56c),
  mathbf: alphabet(0x1d400),
  boldsymbol: alphabet(0x1d400),
}

const TEXT = new Set(['text', 'mathrm', 'textrm', 'textbf', 'textit', 'mathit', 'operatorname', 'mathsf', 'mathtt', 'textsf', 'texttt', 'emph'])

class Parser {
  private i = 0
  private readonly s: string
  constructor(s: string) {
    this.s = s
  }

  parse(stop?: string): string {
    let out = ''
    while (this.i < this.s.length) {
      const c = this.s[this.i]
      if (stop !== undefined && c === stop) return out
      if (c === '{') {
        this.i++
        out += this.parse('}')
        this.i++
      } else if (c === '^' || c === '_') {
        this.i++
        out += script(this.argument(), c === '^' ? SUPER : SUB, c)
      } else if (c === '\\') {
        out += this.command()
      } else if (c === '~') {
        out += ' '
        this.i++
      } else if (c === "'") {
        out += '′'
        this.i++
      } else if (c === '-') {
        out += '−'
        this.i++
      } else {
        out += c
        this.i++
      }
    }
    return out
  }

  // One argument: a {group}, a \command, or a single character.
  private argument(): string {
    while (this.s[this.i] === ' ') this.i++
    const c = this.s[this.i]
    if (c === undefined) return ''
    if (c === '{') {
      this.i++
      const inner = this.parse('}')
      this.i++
      return inner
    }
    if (c === '\\') return this.command()
    this.i++
    return c === '-' ? '−' : c
  }

  private rawArgument(): string {
    while (this.s[this.i] === ' ') this.i++
    if (this.s[this.i] !== '{') return this.s[this.i++] ?? ''
    let depth = 0
    const start = this.i
    for (; this.i < this.s.length; this.i++) {
      if (this.s[this.i] === '{') depth++
      if (this.s[this.i] === '}' && --depth === 0) break
    }
    this.i++
    return this.s.slice(start + 1, this.i - 1)
  }

  private command(): string {
    this.i++
    const letters = /^[A-Za-z]+/.exec(this.s.slice(this.i))
    const name = letters ? letters[0] : (this.s[this.i] ?? '')
    this.i += name.length

    if (name === 'frac' || name === 'dfrac' || name === 'tfrac' || name === 'cfrac') {
      const top = this.argument()
      const bottom = this.argument()
      return `${group(top)}/${group(bottom)}`
    }
    if (name === 'binom') {
      const n = this.argument()
      const k = this.argument()
      return `C(${n}, ${k})`
    }
    if (name === 'sqrt') {
      let index = ''
      if (this.s[this.i] === '[') {
        const close = this.s.indexOf(']', this.i)
        index = new Parser(this.s.slice(this.i + 1, close)).parse()
        this.i = close + 1
      }
      const body = this.argument()
      const radical =
        index === '' ? '√' : index === '3' ? '∛' : index === '4' ? '∜' : `${script(index, SUPER, '^')}√`
      return radical + group(body)
    }
    if (COMBINING[name]) {
      const mark = COMBINING[name]
      const chars = [...this.argument()]
      // A line over or under a run marks every character; an accent, the last.
      return WIDE.has(name)
        ? chars.map(char => char + mark).join('')
        : chars.join('') + mark
    }
    if (FONTS[name]) return [...this.argument()].map(FONTS[name]).join('')
    if (TEXT.has(name)) return this.rawArgument()
    if (name === 'begin' || name === 'end') {
      this.rawArgument()
      return ''
    }
    if (name === '\\') return '; '
    if (DROPPED.has(name)) return ''
    return SYMBOLS[name] ?? `\\${name}`
  }
}

// x^{ab} as superscripts when every character has one, else x^(ab).
function script(body: string, table: Record<string, string>, mark: string): string {
  const chars = [...body]
  if (chars.length > 0 && chars.every(char => table[char])) return chars.map(char => table[char]).join('')
  return chars.length === 1 ? `${mark}${body}` : `${mark}(${body})`
}

// a/b needs no parentheses around a single symbol or number.
function group(text: string): string {
  return /^[\p{L}\p{N}.′]+$/u.test(text) || [...text].length === 1 ? text : `(${text})`
}

export function toUnicode(latex: string): string {
  return new Parser(latex.trim()).parse().replace(/\s+/g, ' ').trim()
}
