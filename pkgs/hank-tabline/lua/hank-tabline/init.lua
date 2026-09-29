-- Posting-style header: a row of tab sections and an optional underline rail.
-- Sections only supply items; buffers, the project label and anything registered
-- through `sections` / `sidebars` (e.g. hank-panels) are rendered the same way.
-- The same tabs can also head a bottom panel (`bottom`), drawn over the separator
-- above that panel and its winbar.
local M = {}
local api = vim.api
local ns = api.nvim_create_namespace('hank_tabline')
local slice = require('hank-tabline.slice')
-- A rail is one buffer line of track in a float: `top` under the tab row, `bottom`
-- under the bottom panel's tabs (its first line holds the tabs themselves).
local function rail(line, ft) return { line = line, ft = ft, target = {}, generation = 0 } end
local S = { sections = {}, blocks = {}, placed = {}, zones = {}, clicks = {}, reserved = {},
  top = rail(0, 'hank_tabline'), bottom = rail(1, 'hank_tabline_strip') }
S.bottom.placed, S.bottom.sections = {}, {}

local function valid(win)
  return win and api.nvim_win_is_valid(win)
end

local function palette()
  local p = S.opts.palette()
  local surface = p.mantle or p.base
  -- With the rail the lit segment already marks the active tab, so its label only
  -- brightens; without it the label carries the mark as a filled block.
  api.nvim_set_hl(0, 'HankTablineSelected', S.opts.underline and { fg = p.text or p.green, bg = p.base, bold = true }
    or { fg = p.crust, bg = p.green, bold = true })
  api.nvim_set_hl(0, 'HankTablineInactive', { fg = p.overlay2, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineTrack', { fg = p.overlay0, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineAccent', { fg = p.green, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineProject', { fg = p.green, bg = p.base, bold = true })
  api.nvim_set_hl(0, 'HankTablineIcon', { fg = p.green, bg = p.base, bold = true })
  -- Sidebar blocks and bottom tabs sit on the panels' own surface (mantle).
  api.nvim_set_hl(0, 'HankTablinePanel', { fg = p.overlay2, bg = surface })
  api.nvim_set_hl(0, 'HankTablinePanelIcon', { fg = p.green, bg = surface, bold = true })
  api.nvim_set_hl(0, 'HankTablinePanelLabel', { fg = p.green, bg = surface, bold = true })
  api.nvim_set_hl(0, 'HankTablinePanelTrack', { fg = p.overlay0, bg = surface })
  api.nvim_set_hl(0, 'HankTablinePanelAccent', { fg = p.green, bg = surface })
  api.nvim_set_hl(0, 'HankTablinePanelTab', { fg = p.text or p.green, bg = surface, bold = true })
end

-- 'block' sections mark the active item with a filled label, 'icon' sections only
-- recolour it (the rail and the filled/outline glyph carry the rest), 'tab'
-- sections (bottom panels) brighten the active label.
local function highlight(section, item, surface)
  if item.hl then return item.hl end
  if section.style == 'label' then return surface and 'HankTablinePanelLabel' or 'HankTablineProject' end
  if section.style == 'tab' then return item.active and 'HankTablinePanelTab' or 'HankTablinePanel' end
  if not item.active then return surface and 'HankTablinePanel' or 'HankTablineInactive' end
  if section.style == 'icon' then return surface and 'HankTablinePanelIcon' or 'HankTablineIcon' end
  return 'HankTablineSelected'
end

local function build(section, ctx, surface)
  local items, width, active = {}, 0, nil
  for _, item in ipairs(section.items(ctx) or {}) do
    local w = vim.fn.strdisplaywidth(item.text)
    local entry = { id = item.id, text = item.text, active = item.active, hl = highlight(section, item, surface),
      start = width, finish = width + w }
    items[#items + 1] = entry
    width = width + w
    if item.active then active = entry end
  end
  return { key = section.key, section = section, items = items, width = width, active = active, offset = 0 }
end

-- Lit rail segments: the active item of each placed section, minus its padding.
local function targets(placed)
  local out = {}
  for _, b in ipairs(placed) do
    if b.active then
      local pad = b.section.pad or 1
      local s = math.max(b.x, b.x + b.active.start - b.offset + pad)
      local f = math.min(b.x + b.room, b.x + b.active.finish - b.offset - pad)
      if f > s then out[b.key] = { s, f } end
    end
  end
  return out
end

local function collect()
  local columns = vim.o.columns
  local ctx = { columns = columns }
  local placed, zones, left, right, fill_to = {}, {}, 0, columns, 0
  local function place(b, x, room)
    b.x, b.room = x, math.max(0, room)
    placed[#placed + 1] = b
  end
  local function zone(from, to, kind)
    for col = math.max(0, from), math.min(columns, to) - 1 do zones[col] = kind end
    if kind == 'surface' then fill_to = math.max(fill_to, math.min(columns, to)) end
  end
  local function inner(block)
    local built, used = {}, 0
    for _, section in ipairs(block.sections) do
      built[#built + 1] = build(section, ctx, true)
      used = used + built[#built].width
    end
    return built, used
  end
  -- A block is only drawn while one of its panels is open, i.e. while there is
  -- a sidebar underneath it.
  local function open(built)
    for _, b in ipairs(built) do
      if b.active then return true end
    end
    return false
  end

  -- Sidebar blocks cover the sidebar column: fixed width, their own surface, and a
  -- gap toward the buffer tabs so neither the tab row nor the rail runs through.
  local block = S.blocks.left
  local built, used
  if block then built, used = inner(block) end
  if block and not open(built) then
    -- No sidebar: the project title simply leads the tab row.
    if block.project then
      local title = build(block.project, ctx)
      place(title, left, math.min(title.width, columns))
      left = left + title.room
    end
  elseif block then
    local w = math.min(block.width, columns)
    -- Title on the outer edge, icons at a fixed spot toward the files (one cell
    -- off the gap), so a longer project name never moves a click target.
    local x = math.max(0, w - used - block.margin)
    if block.project then
      local title = build(block.project, { columns = columns, width = x }, true)
      place(title, 0, math.min(title.width, x))
    end
    for _, b in ipairs(built) do
      place(b, x, math.min(b.width, w - x))
      x = x + b.room
    end
    zone(0, w, 'surface')
    zone(w, w + block.gap, 'gap')
    left = math.min(columns, w + block.gap)
  end
  block = S.blocks.right
  if block then
    built, used = inner(block)
    local w = math.min(block.width, right - left - block.gap)
    if open(built) and w > 0 then
      local x = right - w
      zone(x, right, 'surface')
      zone(x - block.gap, x, 'gap')
      right = x - block.gap
      x = x + math.min(block.margin, math.max(0, w - used))
      for _, b in ipairs(built) do
        place(b, x, math.min(b.width, columns - x))
        x = x + b.room
      end
    end
  end
  for _, section in ipairs(S.sections) do
    if section.align == 'left' then
      local b = build(section, ctx)
      if b.width > 0 then
        place(b, left, math.min(b.width, right - left))
        left = left + b.room
      end
    end
  end
  for i = #S.sections, 1, -1 do
    local section = S.sections[i]
    if section.align == 'right' then
      local b = build(section, ctx)
      if b.width > 0 and right - b.width >= left then
        right = right - b.width
        place(b, right, b.width)
      end
    end
  end
  for _, section in ipairs(S.sections) do
    if section.align == 'fill' then
      local b = build(section, ctx)
      place(b, left, right - left)
      if b.active then
        -- Match Posting's scroll-to-center behavior while keeping short lists left aligned.
        b.offset = math.max(0, math.min(math.floor((b.active.start + b.active.finish - b.room) / 2), b.width - b.room))
      end
    end
  end
  table.sort(placed, function(a, b) return a.x < b.x end)
  S.placed, S.zones, S.fill_to = placed, zones, fill_to
  S.top.zones, S.top.width, S.top.target = zones, columns, targets(placed)
end

-- The bottom panel's tabs, left aligned inside the strip.
local function collect_bottom()
  local B = S.bottom
  B.placed, B.target = {}, {}
  if not valid(B.win) then return end
  local ctx, x = { columns = B.width }, 1
  for _, section in ipairs(B.sections) do
    local b = build(section, ctx, true)
    if b.width > 0 and x < B.width then
      b.x, b.room = x, math.min(b.width, B.width - x)
      B.placed[#B.placed + 1] = b
      x = x + b.room
    end
  end
  B.target = targets(B.placed)
end

-- Visible part of an item, in screen columns.
local function visible(b, item)
  local left, right = math.max(item.start, b.offset), math.min(item.finish, b.offset + b.room)
  return b.x + left - b.offset, b.x + right - b.offset, left, right
end

function M.render()
  local parts, col, zones = {}, 0, S.zones
  S.clicks = {}
  -- Blank cells take the colour of the zone they sit in.
  local function blank(to)
    while col < to do
      local surface = zones[col] == 'surface'
      local stop = col + 1
      while stop < to and (zones[stop] == 'surface') == surface do stop = stop + 1 end
      parts[#parts + 1] = ('%%#%s#%%0@v:lua.HankTablineNoop@%s%%X'):format(
        surface and 'HankTablinePanel' or 'HankTablineInactive', string.rep(' ', stop - col))
      col = stop
    end
  end
  for _, b in ipairs(S.placed) do
    blank(b.x)
    for _, item in ipairs(b.items) do
      local _, screen_right, left, right = visible(b, item)
      if left < right then
        local text = slice(item.text, left - item.start, right - left):gsub('%%', '%%%%')
        local nr, handler = 0, 'HankTablineNoop'
        if b.section.click then
          S.clicks[#S.clicks + 1] = { section = b.section, id = item.id }
          nr, handler = #S.clicks, 'HankTablineClick'
        end
        parts[#parts + 1] = ('%%#%s#%%%d@v:lua.%s@%s%%X'):format(item.hl, nr, handler, text)
        col = math.max(col, screen_right)
      end
    end
  end
  blank(S.fill_to or 0)
  parts[#parts + 1] = '%#HankTablineInactive#%='
  return table.concat(parts)
end

-- Screen layout of the visible items, for tests and integrations. `which` is 'top'
-- (default) or 'bottom'; bottom columns are screen columns too.
function M.layout(which)
  local out, placed, dx = {}, S.placed, 0
  if which == 'bottom' then placed, dx = S.bottom.placed, S.bottom.col or 0 end
  for _, b in ipairs(placed) do
    for _, item in ipairs(b.items) do
      local left, right = visible(b, item)
      if right > left then out[#out + 1] = { section = b.key, id = item.id, col = left + dx, width = right - left } end
    end
  end
  return out
end

local function item_at(placed, col)
  for _, b in ipairs(placed) do
    for _, item in ipairs(b.items) do
      local left, right = visible(b, item)
      if col >= left and col < right then return b.section, item end
    end
  end
end

local function draw(R, spans)
  if not valid(R.win) then return end
  local zones, list = R.zones or {}, {}
  for _, span in pairs(spans) do
    local s, f = math.floor(span[1] * 2 + 0.5) / 2, math.floor(span[2] * 2 + 0.5) / 2
    if f > s then list[#list + 1] = { s, f } end
  end
  local cells, groups = {}, {}
  for col = 0, R.width - 1 do
    local char, accent
    local kind = R.surface and 'surface' or zones[col]
    if kind == 'gap' then
      char = ' '
    else
      for _, span in ipairs(list) do
        local s, f = span[1], span[2]
        if col >= s and col + 1 <= f then
          char, accent = '━', true
        elseif col < s and col + 1 > s and col + 1 <= f then
          char, accent = '╺', true
        elseif col >= s and col < f and col + 1 > f then
          char, accent = '╸', true
        end
        if accent then break end
      end
      if not accent then
        -- Half-cell gaps on either side of a lit segment, as Textual's Bar draws them.
        for _, span in ipairs(list) do
          if col + 1 == span[1] then char = '╸'; break end
          if col == span[2] then char = '╺'; break end
        end
      end
    end
    cells[#cells + 1] = char or '━'
    local surface = kind == 'surface'
    if accent then
      groups[#groups + 1] = surface and 'HankTablinePanelAccent' or 'HankTablineAccent'
    else
      -- Plain track outside blocks is the window's own Normal (HankTablineTrack).
      groups[#groups + 1] = surface and 'HankTablinePanelTrack' or false
    end
  end
  vim.bo[R.buf].modifiable = true
  api.nvim_buf_set_lines(R.buf, R.line, R.line + 1, false, { table.concat(cells) })
  vim.bo[R.buf].modifiable = false
  api.nvim_buf_clear_namespace(R.buf, ns, R.line, R.line + 1)
  -- Rail glyphs are three bytes and gap spaces one, so walk byte offsets.
  local byte, group, from = 0, false, 0
  for i, cell in ipairs(cells) do
    if groups[i] ~= group then
      if group then api.nvim_buf_set_extmark(R.buf, ns, R.line, from, { end_col = byte, hl_group = group }) end
      group, from = groups[i], byte
    end
    byte = byte + #cell
  end
  if group then api.nvim_buf_set_extmark(R.buf, ns, R.line, from, { end_col = byte, hl_group = group }) end
  R.position = vim.deepcopy(spans)
end

local function animate(R, instant)
  local target = R.target
  if not instant and R.destination and vim.deep_equal(target, R.destination) then return end
  R.destination = vim.deepcopy(target)
  R.generation = R.generation + 1
  local generation = R.generation
  if instant or not S.opts.animate or S.opts.duration == 0 or not R.position then draw(R, target); return end
  local origin, begun = R.position, vim.uv.hrtime()
  local function step()
    if generation ~= R.generation or not valid(R.win) then return end
    local t = math.min(1, (vim.uv.hrtime() - begun) / (S.opts.duration * 1e9))
    local eased = t < 0.5 and 4 * t ^ 3 or 1 - (-2 * t + 2) ^ 3 / 2
    -- Segments that exist on both ends glide; new ones appear in place.
    local frame = {}
    for key, to in pairs(target) do
      local from = origin[key]
      frame[key] = from and { from[1] + (to[1] - from[1]) * eased, from[2] + (to[2] - from[2]) * eased } or to
    end
    draw(R, frame)
    if t < 1 then vim.defer_fn(step, 16) end
  end
  step()
end

-- The bottom tabs' first line: labels on the panel surface (the float's Normal).
local function paint_bottom()
  local B = S.bottom
  if not valid(B.win) then return end
  local parts, marks, col, bytes = {}, {}, 0, 0
  local function put(text, group)
    if group then marks[#marks + 1] = { bytes, bytes + #text, group } end
    parts[#parts + 1] = text
    bytes = bytes + #text
  end
  for _, b in ipairs(B.placed) do
    for _, item in ipairs(b.items) do
      local screen_left, screen_right, left, right = visible(b, item)
      if left < right then
        if screen_left > col then put(string.rep(' ', screen_left - col)) end
        put(slice(item.text, left - item.start, right - left), item.hl)
        col = screen_right
      end
    end
  end
  if col < B.width then put(string.rep(' ', B.width - col)) end
  vim.bo[B.buf].modifiable = true
  api.nvim_buf_set_lines(B.buf, 0, 1, false, { table.concat(parts) })
  vim.bo[B.buf].modifiable = false
  api.nvim_buf_clear_namespace(B.buf, ns, 0, 1)
  for _, m in ipairs(marks) do api.nvim_buf_set_extmark(B.buf, ns, 0, m[1], { end_col = m[2], hl_group = m[3] }) end
end

local function scratch(R, lines)
  if R.buf and api.nvim_buf_is_valid(R.buf) then return end
  R.buf = api.nvim_create_buf(false, true)
  vim.bo[R.buf].filetype = R.ft
  vim.bo[R.buf].bufhidden = 'hide'
  vim.bo[R.buf].undolevels = -1
  api.nvim_buf_set_lines(R.buf, 0, -1, false, lines)
  vim.bo[R.buf].modifiable = false
end

local function hide(R)
  if valid(R.win) then api.nvim_win_close(R.win, true) end
  R.win = nil
end

-- Floats belong to a tabpage, so a rail from another tabpage is replaced.
local function show(R, config, surface)
  if valid(R.win) and api.nvim_win_get_tabpage(R.win) ~= api.nvim_get_current_tabpage() then hide(R) end
  config = vim.tbl_extend('force', { relative = 'editor', height = 1, focusable = false, mouse = true,
    style = 'minimal', border = 'none', zindex = 20 }, config)
  if valid(R.win) then
    api.nvim_win_set_config(R.win, config)
    return false
  end
  R.win = api.nvim_open_win(R.buf, false, config)
  local group = surface and 'HankTablinePanel' or 'HankTablineTrack'
  vim.wo[R.win].winhighlight = ('Normal:%s,EndOfBuffer:%s'):format(group, group)
  R.destination = nil
  return true
end

-- The split the bottom tabs sit on: it needs a window above it (whose separator
-- row takes the labels) and, with the rail, a text line below its winbar.
local function bottom_anchor()
  if not S.opts.bottom then return nil end
  local ok, win = pcall(S.opts.bottom.anchor)
  if not ok or not valid(win) or api.nvim_win_get_config(win).relative ~= '' then return nil end
  if api.nvim_win_get_tabpage(win) ~= api.nvim_get_current_tabpage() then return nil end
  if api.nvim_win_get_position(win)[1] < 2 then return nil end
  if api.nvim_win_get_height(win) < (S.opts.underline and 2 or 1) then return nil end
  return win
end

local function geometry()
  local current_tab = api.nvim_get_current_tabpage()
  for win in pairs(S.reserved) do
    if not valid(win) then S.reserved[win] = nil end
  end
  local enough_room = S.opts.underline and vim.o.lines >= 6
  for _, win in ipairs(api.nvim_tabpage_list_wins(current_tab)) do
    if api.nvim_win_get_config(win).relative == '' then
      local top = api.nvim_win_get_position(win)[1] == 1
      if top and api.nvim_win_get_height(win) < 2 then enough_room = false end
    end
  end
  local anchor = bottom_anchor()
  for _, win in ipairs(api.nvim_tabpage_list_wins(current_tab)) do
    if api.nvim_win_get_config(win).relative == '' then
      local top = enough_room and api.nvim_win_get_position(win)[1] == 1
      -- The bottom rail lives in the anchor's winbar, as the top one does in the top windows'.
      if top or (win == anchor and S.opts.underline) then
        if S.reserved[win] == nil then S.reserved[win] = vim.wo[win].winbar end
        if vim.wo[win].winbar ~= ' ' then vim.wo[win].winbar = ' ' end
      elseif S.reserved[win] ~= nil or (S.opts.underline and vim.wo[win].winbar == ' ') then
        vim.wo[win].winbar = S.reserved[win] or ''
        S.reserved[win] = nil
      end
    end
  end
  if enough_room then
    scratch(S.top, { '' })
    show(S.top, { row = 1, col = 0, width = vim.o.columns })
  else
    hide(S.top)
  end
  local B = S.bottom
  if anchor then
    scratch(B, { '', '' })
    local position = api.nvim_win_get_position(anchor)
    B.col, B.width = position[2], api.nvim_win_get_width(anchor)
    local created = show(B, { row = position[1] - 1, col = B.col, width = B.width,
      height = S.opts.underline and 2 or 1 }, true)
    -- A freshly opened panel lights its tab in place instead of gliding in.
    if created then B.position = nil end
  else
    hide(B)
  end
end

function M.refresh(instant)
  if S.updating or S.exiting then return end
  S.updating = true
  local ok, err = pcall(function()
    for _, list in ipairs({ S.sections, S.bottom.sections }) do
      for _, section in ipairs(list) do
        if section.update then section.update() end
      end
    end
    geometry()
    collect()
    collect_bottom()
    vim.cmd.redrawtabline()
    if valid(S.top.win) then animate(S.top, instant) end
    if valid(S.bottom.win) then
      paint_bottom()
      if S.opts.underline then animate(S.bottom, instant) end
    end
  end)
  S.updating = false
  if not ok then vim.notify('hank-tabline: ' .. tostring(err), vim.log.levels.ERROR) end
end

local function queue(instant)
  if S.updating or S.exiting then return end
  S.instant = S.instant or instant
  if S.pending then return end
  S.pending = true
  vim.schedule(function()
    S.pending = false
    local now = S.instant
    S.instant = false
    M.refresh(now)
  end)
end
M.queue = queue

-- Snacks re-applies its own window options on every layout pass, so a sidebar
-- picker has to carry the reserved winbar itself. Use as a picker `on_show`.
function M.reserve_snacks(picker)
  if not (S.opts and S.opts.underline and picker.layout and picker.layout.split) then return end
  picker.layout.root.opts.wo.winbar = ' '
  vim.wo[picker.layout.root.win].winbar = ' '
  picker.layout:update()
end

function M.setup(opts)
  S.opts = vim.tbl_extend('force', {
    duration = 0.3, animate = true, underline = false, project = false, sections = {}, sidebars = {},
  }, opts or {})
  S.bottom.surface = true
  S.bottom.sections = {}
  -- `bottom = { sections = {...}, anchor = function() return win end }`: tabs over
  -- the split that anchor() returns (e.g. hank-panels' open bottom panel).
  for i, section in ipairs(S.opts.bottom and S.opts.bottom.sections or {}) do
    S.bottom.sections[i] = setmetatable({ align = 'bottom', key = 'bottom-' .. i }, { __index = section })
  end
  S.sections, S.blocks = {}, {}
  local function add(section, align, key)
    local wrapped = setmetatable({ align = align, key = key }, { __index = section })
    S.sections[#S.sections + 1] = wrapped
    return wrapped
  end
  local function block(spec, side)
    if not spec then return nil end
    local sections = {}
    for i, section in ipairs(spec.sections or {}) do sections[i] = add(section, 'block', side .. '-block-' .. i) end
    return { width = spec.width, gap = spec.gap or 1, margin = spec.margin or 1, sections = sections }
  end
  S.blocks.left = block(S.opts.sidebars.left, 'left')
  if S.opts.project then
    -- With a left sidebar block the label becomes its title; otherwise it leads the row.
    local project = add(require('hank-tabline.project'), S.blocks.left and 'block' or 'left', 'project')
    if S.blocks.left then S.blocks.left.project = project end
  end
  for i, section in ipairs(S.opts.sections.left or {}) do add(section, 'left', 'left-' .. i) end
  add(require('hank-tabline.buffers'), 'fill', 'buffers')
  for i, section in ipairs(S.opts.sections.right or {}) do add(section, 'right', 'right-' .. i) end
  S.blocks.right = block(S.opts.sidebars.right, 'right')

  local group = api.nvim_create_augroup('hank_tabline', { clear = true })
  palette()
  vim.o.showtabline = 2
  vim.o.tabline = "%!v:lua.require('hank-tabline').render()"
  _G.HankTablineClick = function(nr, _, button)
    local entry = S.clicks[nr]
    if entry then entry.section.click(entry.id, button) end
  end
  _G.HankTablineNoop = function() end
  api.nvim_create_autocmd({ 'UIEnter', 'VimEnter', 'VimResized', 'WinResized', 'TabEnter', 'WinNew', 'WinClosed', 'DirChanged' }, {
    group = group, callback = function() queue(true) end,
  })
  api.nvim_create_autocmd({ 'BufEnter', 'WinEnter', 'BufAdd', 'BufDelete', 'BufFilePost', 'BufModifiedSet', 'BufWritePost',
    'FileType', 'DiagnosticChanged' }, {
    group = group, callback = function() queue(false) end,
  })
  api.nvim_create_autocmd('OptionSet', {
    group = group, pattern = { 'winbar', 'buflisted', 'modified' }, callback = function() queue(true) end,
  })
  api.nvim_create_autocmd('ColorScheme', { group = group, callback = function() palette(); queue(true) end })
  api.nvim_create_autocmd('VimLeavePre', { group = group, callback = function()
    S.exiting = true
    S.top.generation, S.bottom.generation = S.top.generation + 1, S.bottom.generation + 1
  end })
  vim.keymap.set({ 'n', 'i', 'v', 't' }, '<LeftMouse>', function()
    local mouse = vim.fn.getmousepos()
    local section, item
    if valid(S.top.win) and mouse.winid == S.top.win then
      section, item = item_at(S.placed, mouse.screencol - 1)
    elseif valid(S.bottom.win) and mouse.winid == S.bottom.win then
      section, item = item_at(S.bottom.placed, mouse.wincol - 1)
    else
      return '<LeftMouse>'
    end
    if section and section.click then section.click(item.id, 'l') end
    return ''
  end, { expr = true, desc = 'Select a tab from the header underline or the bottom panel tabs' })
  queue(true)
end

return M
