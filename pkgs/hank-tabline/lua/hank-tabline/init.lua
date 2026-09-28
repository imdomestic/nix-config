-- Posting-style header: a row of tab sections and an optional underline rail.
-- Sections only supply items; buffers, the project label and anything registered
-- through `sections` / `sidebars` (e.g. hank-panels) are rendered the same way.
local M = {}
local api = vim.api
local ns = api.nvim_create_namespace('hank_tabline')
local slice = require('hank-tabline.slice')
local S = { sections = {}, blocks = {}, placed = {}, zones = {}, clicks = {}, target = {}, reserved = {}, generation = 0 }

local function valid(win)
  return win and api.nvim_win_is_valid(win)
end

local function palette()
  local p = S.opts.palette()
  local surface = p.mantle or p.base
  api.nvim_set_hl(0, 'HankTablineSelected', { fg = p.crust, bg = p.green, bold = true })
  api.nvim_set_hl(0, 'HankTablineInactive', { fg = p.overlay2, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineTrack', { fg = p.overlay0, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineAccent', { fg = p.green, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineProject', { fg = p.green, bg = p.base, bold = true })
  api.nvim_set_hl(0, 'HankTablineIcon', { fg = p.green, bg = p.base, bold = true })
  -- Sidebar blocks sit on the sidebar's own surface (NormalFloat is mantle in Evergarden).
  api.nvim_set_hl(0, 'HankTablinePanel', { fg = p.overlay2, bg = surface })
  api.nvim_set_hl(0, 'HankTablinePanelIcon', { fg = p.green, bg = surface, bold = true })
  api.nvim_set_hl(0, 'HankTablinePanelLabel', { fg = p.green, bg = surface, bold = true })
  api.nvim_set_hl(0, 'HankTablinePanelTrack', { fg = p.overlay0, bg = surface })
  api.nvim_set_hl(0, 'HankTablinePanelAccent', { fg = p.green, bg = surface })
end

-- 'block' sections mark the active item with a filled label, 'icon' sections only
-- recolour it (the rail and the filled/outline glyph carry the rest).
local function highlight(section, item, surface)
  if item.hl then return item.hl end
  if section.style == 'label' then return surface and 'HankTablinePanelLabel' or 'HankTablineProject' end
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

  -- Sidebar blocks cover the sidebar column: fixed width, their own surface, and a
  -- gap toward the buffer tabs so neither the tab row nor the rail runs through.
  local block = S.blocks.left
  if block then
    local w = math.min(block.width, columns)
    local built, used = inner(block)
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
    local built, used = inner(block)
    local w = math.min(block.width, right - left - block.gap)
    -- Only shown while one of its panels is available (e.g. a Lean buffer is open).
    if used > 0 and w > 0 then
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
  S.placed, S.zones, S.fill_to, S.target = placed, zones, fill_to, {}
  for _, b in ipairs(placed) do
    if b.active then
      local pad = b.section.pad or 1
      local s = math.max(b.x, b.x + b.active.start - b.offset + pad)
      local f = math.min(b.x + b.room, b.x + b.active.finish - b.offset - pad)
      if f > s then S.target[b.key] = { s, f } end
    end
  end
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

-- Screen layout of the visible items, for tests and integrations.
function M.layout()
  local out = {}
  for _, b in ipairs(S.placed) do
    for _, item in ipairs(b.items) do
      local left, right = visible(b, item)
      if right > left then out[#out + 1] = { section = b.key, id = item.id, col = left, width = right - left } end
    end
  end
  return out
end

local function item_at(col)
  for _, b in ipairs(S.placed) do
    for _, item in ipairs(b.items) do
      local left, right = visible(b, item)
      if col >= left and col < right then return b.section, item end
    end
  end
end

local function draw(spans)
  if not valid(S.bar) then return end
  local zones, list = S.zones, {}
  for _, span in pairs(spans) do
    local s, f = math.floor(span[1] * 2 + 0.5) / 2, math.floor(span[2] * 2 + 0.5) / 2
    if f > s then list[#list + 1] = { s, f } end
  end
  local cells, groups = {}, {}
  for col = 0, vim.o.columns - 1 do
    local char, accent
    if zones[col] == 'gap' then
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
    local surface = zones[col] == 'surface'
    if accent then
      groups[#groups + 1] = surface and 'HankTablinePanelAccent' or 'HankTablineAccent'
    else
      -- Plain track outside blocks is the window's own Normal (HankTablineTrack).
      groups[#groups + 1] = surface and 'HankTablinePanelTrack' or false
    end
  end
  vim.bo[S.buf].modifiable = true
  api.nvim_buf_set_lines(S.buf, 0, -1, false, { table.concat(cells) })
  vim.bo[S.buf].modifiable = false
  api.nvim_buf_clear_namespace(S.buf, ns, 0, -1)
  -- Rail glyphs are three bytes and gap spaces one, so walk byte offsets.
  local byte, group, from = 0, false, 0
  for i, cell in ipairs(cells) do
    if groups[i] ~= group then
      if group then api.nvim_buf_set_extmark(S.buf, ns, 0, from, { end_col = byte, hl_group = group }) end
      group, from = groups[i], byte
    end
    byte = byte + #cell
  end
  if group then api.nvim_buf_set_extmark(S.buf, ns, 0, from, { end_col = byte, hl_group = group }) end
  S.position = vim.deepcopy(spans)
end

local function animate(instant)
  local target = S.target
  if not instant and S.destination and vim.deep_equal(target, S.destination) then return end
  S.destination = vim.deepcopy(target)
  S.generation = S.generation + 1
  local generation = S.generation
  if instant or not S.opts.animate or S.opts.duration == 0 or not S.position then draw(target); return end
  local origin, begun = S.position, vim.uv.hrtime()
  local function step()
    if generation ~= S.generation or not valid(S.bar) then return end
    local t = math.min(1, (vim.uv.hrtime() - begun) / (S.opts.duration * 1e9))
    local eased = t < 0.5 and 4 * t ^ 3 or 1 - (-2 * t + 2) ^ 3 / 2
    -- Segments that exist on both ends glide; new ones appear in place.
    local frame = {}
    for key, to in pairs(target) do
      local from = origin[key]
      frame[key] = from and { from[1] + (to[1] - from[1]) * eased, from[2] + (to[2] - from[2]) * eased } or to
    end
    draw(frame)
    if t < 1 then vim.defer_fn(step, 16) end
  end
  step()
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
  for _, win in ipairs(api.nvim_tabpage_list_wins(current_tab)) do
    if api.nvim_win_get_config(win).relative == '' then
      local top = enough_room and api.nvim_win_get_position(win)[1] == 1
      if top then
        if S.reserved[win] == nil then S.reserved[win] = vim.wo[win].winbar end
        if vim.wo[win].winbar ~= ' ' then vim.wo[win].winbar = ' ' end
      elseif S.reserved[win] ~= nil or (S.opts.underline and vim.wo[win].winbar == ' ') then
        vim.wo[win].winbar = S.reserved[win] or ''
        S.reserved[win] = nil
      end
    end
  end
  if valid(S.bar) and (not enough_room or api.nvim_win_get_tabpage(S.bar) ~= current_tab) then
    api.nvim_win_close(S.bar, true)
    S.bar = nil
  end
  if not enough_room then return end
  if not S.buf or not api.nvim_buf_is_valid(S.buf) then
    S.buf = api.nvim_create_buf(false, true)
    vim.bo[S.buf].filetype = 'hank_tabline'
    vim.bo[S.buf].bufhidden = 'hide'
    vim.bo[S.buf].undolevels = -1
  end
  local config = { relative = 'editor', row = 1, col = 0, width = vim.o.columns, height = 1,
    focusable = false, mouse = true, style = 'minimal', border = 'none', zindex = 20 }
  if valid(S.bar) then
    api.nvim_win_set_config(S.bar, config)
  else
    S.bar = api.nvim_open_win(S.buf, false, config)
    vim.wo[S.bar].winhighlight = 'Normal:HankTablineTrack,EndOfBuffer:HankTablineTrack'
    S.destination = nil
  end
end

function M.refresh(instant)
  if S.updating or S.exiting then return end
  S.updating = true
  local ok, err = pcall(function()
    for _, section in ipairs(S.sections) do
      if section.update then section.update() end
    end
    geometry()
    collect()
    vim.cmd.redrawtabline()
    if valid(S.bar) then animate(instant) end
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
  api.nvim_create_autocmd({ 'BufEnter', 'WinEnter', 'BufAdd', 'BufDelete', 'BufFilePost', 'BufModifiedSet', 'BufWritePost' }, {
    group = group, callback = function() queue(false) end,
  })
  api.nvim_create_autocmd('OptionSet', {
    group = group, pattern = { 'winbar', 'buflisted', 'modified' }, callback = function() queue(true) end,
  })
  api.nvim_create_autocmd('ColorScheme', { group = group, callback = function() palette(); queue(true) end })
  api.nvim_create_autocmd('VimLeavePre', { group = group, callback = function() S.exiting = true; S.generation = S.generation + 1 end })
  vim.keymap.set({ 'n', 'i', 'v', 't' }, '<LeftMouse>', function()
    local mouse = vim.fn.getmousepos()
    if valid(S.bar) and mouse.winid == S.bar then
      local section, item = item_at(mouse.screencol - 1)
      if section and section.click then section.click(item.id, 'l') end
      return ''
    end
    return '<LeftMouse>'
  end, { expr = true, desc = 'Select a tab from the header underline' })
  queue(true)
end

return M
