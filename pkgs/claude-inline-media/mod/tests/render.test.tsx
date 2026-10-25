import { expect, test } from 'claude-code/testing'

const reply = (text: string) =>
  ({
    plugin: 'inline-media',
    surface: 'terminal',
    component: 'AssistantMessage',
    props: { text, isFirstOfReply: true },
    viewport: { columns: 100, rows: 40 },
  }) as const

test('inline math reaches the engine as Unicode', async ($, on) => {
  // Nothing draws beneath the plugin: this hook stands for the engine.
  on('ui.render', { component: 'AssistantMessage' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>engine: {e.props.text}</Text>
  })

  const ui = await $.ui.mount(reply('so $x^2 + y_1$ holds, at $5 and $10'))
  expect((await ui.find({ type: 'Text', text: /engine/ }))?.text).toBe(
    'engine: so x² + y₁ holds, at $5 and $10',
  )
  await ui.unmount()
})

test('display math goes under the part the engine draws', async ($, on) => {
  on('ui.render', { component: 'AssistantMessage' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>engine: {e.props.text}</Text>
  })

  const ui = await $.ui.mount(reply('Gaussian:\n\n$$\n\\int e^{-x^2} dx\n$$\n\nso $a$ is done.'))
  expect((await ui.find({ type: 'Text', text: /engine/ }))?.text).toBe('engine: Gaussian:')
  // Not rendered yet: the formula shows as Unicode until its picture is in.
  expect((await ui.find({ type: 'Text', text: /∫/ }))?.text).toBe('∫ e^(−x²) dx')
  expect((await ui.find({ type: 'Markdown' }))?.text).toBe('so a is done.')
  await ui.unmount()
})

test('a reply without math is left to the engine', async ($, on) => {
  on('ui.render', { component: 'AssistantMessage' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>engine: {e.props.text}</Text>
  })

  const ui = await $.ui.mount(reply('plain words, `$HOME` in code'))
  expect((await ui.find({ type: 'Text' }))?.text).toBe('engine: plain words, `$HOME` in code')
  await ui.unmount()
})

// A 1x1 PNG: drawn as it is, with no thumbnail run.
const DOT = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='

const readCall = (output: unknown) => ({
  tool_use_id: 'toolu_1',
  tool: 'Read',
  input: { file_path: '/tmp/dot.png' },
  isRunning: false,
  isErrored: false,
  isInterrupted: false,
  output,
})

test('a picture Read returned shows under the collapsed group', async ($, on) => {
  on('ui.render', { component: 'ToolGroup' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>Read {e.props.calls.length} file</Text>
  })

  const ui = await $.ui.mount({
    plugin: 'inline-media',
    surface: 'terminal',
    component: 'ToolGroup',
    props: {
      calls: [readCall({ type: 'image', file: { base64: DOT, type: 'image/png', originalSize: 70 } })],
      isActive: false,
      isExpanded: false,
    },
    viewport: { columns: 100, rows: 40 },
  })
  expect((await ui.find({ type: 'Text' }))?.text).toBe('Read 1 file')
  const image = await ui.find({ type: 'Image' })
  expect(image?.props.columns).toBe(2)
  expect(image?.props.rows).toBe(1)
  await ui.unmount()
})

test('a group that read text is left to the engine', async ($, on) => {
  on('ui.render', { component: 'ToolGroup' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>engine group</Text>
  })

  const ui = await $.ui.mount({
    plugin: 'inline-media',
    surface: 'terminal',
    component: 'ToolGroup',
    props: {
      calls: [readCall({ type: 'text', file: { filePath: '/tmp/a.txt', content: 'hi', numLines: 1, startLine: 1, totalLines: 1 } })],
      isActive: false,
      isExpanded: false,
    },
  })
  expect(await ui.find({ type: 'Image' })).toBeUndefined()
  expect((await ui.find({ type: 'Text' }))?.text).toBe('engine group')
  await ui.unmount()
})

test('an image line in a reply becomes a picture slot', async ($, on) => {
  on('ui.render', { component: 'AssistantMessage' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>engine: {e.props.text}</Text>
  })

  // Tests have no file system: the slot says why there is no picture.
  const ui = await $.ui.mount(reply('The chart:\n\n![p95 latency](/tmp/chart.png)\n\nand a [link](https://x.y).'))
  expect((await ui.find({ type: 'Text', text: /engine/ }))?.text).toBe('engine: The chart:')
  expect((await ui.find({ type: 'Text', text: /p95 latency/ }))?.text).toMatch(/^\[p95 latency\] inline-media: /)
  expect((await ui.find({ type: 'Markdown' }))?.text).toBe('and a [link](https://x.y).')
  await ui.unmount()
})

const prompt = (text: string) =>
  ({
    plugin: 'inline-media',
    surface: 'terminal',
    component: 'UserMessage',
    props: { text, origin: { kind: 'composer' }, isExpanded: false },
    viewport: { columns: 100, rows: 40 },
  }) as const

test('a pasted picture shows under the prompt that carried it', async ($, on) => {
  on('ui.render', { component: 'UserMessage' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>you: {e.props.text}</Text>
  })
  on('clock.now', () => ({ value: 10_000 }))
  on('session.messages', () => ({
    value: [
      {
        role: 'user',
        // As the request carries it: reminders merged into the prompt's message.
        content: [
          { type: 'text', text: '<system-reminder>\nproject instructions\n</system-reminder>' },
          { type: 'text', text: '[Image #4] what is this' },
          { type: 'image', source: { type: 'base64', media_type: 'image/png', data: DOT } },
          { type: 'text', text: '[Image: source: /tmp/paste.png]' },
        ],
      },
    ],
  }))

  const ui = await $.ui.mount(prompt('[Image #4] what is this'))
  expect((await ui.find({ type: 'Text' }))?.text).toBe('you: [Image #4] what is this')
  expect((await ui.find({ type: 'Image' }))?.props.alt).toBe('Image #4')
  await ui.unmount()
})

test('a pasted picture shows once its prompt is stored', async ($, on) => {
  on('ui.render', { component: 'UserMessage' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>you: {e.props.text}</Text>
  })
  on('clock.now', () => ({ value: 10_000 }))
  // The row is drawn before the conversation holds it.
  on('session.messages', () => ({ value: [] }))

  const ui = await $.ui.mount(prompt('[Image #5] how big'))
  expect(await ui.find({ type: 'Image' })).toBeUndefined()
  await $.session.append({
    message: {
      type: 'user',
      role: 'user',
      content: [
        { type: 'text', text: '[Image #5] how big' },
        { type: 'image', source: { type: 'base64', media_type: 'image/png', data: DOT } },
      ],
    },
    door: 'prompt',
    origin: { kind: 'composer' },
    uuid: 'row-5',
  })
  expect((await ui.find({ type: 'Image' }))?.props.alt).toBe('Image #5')
  await ui.unmount()
})

test('a prompt with no picture is left to the engine', async ($, on) => {
  on('ui.render', { component: 'UserMessage' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>you: {e.props.text}</Text>
  })

  const ui = await $.ui.mount(prompt('just words'))
  expect(await ui.find({ type: 'Image' })).toBeUndefined()
  await ui.unmount()
})
