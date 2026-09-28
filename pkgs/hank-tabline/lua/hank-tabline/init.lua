local M = {}
local api = vim.api
local ns = api.nvim_create_namespace('hank_tabline')
local S = { tabs = {}, editors = {}, reserved = {}, offset = 0, left = 0, prefix = '', generation = 0 }

local function valid(win)
  return win and api.nvim_win_is_valid(win)
end

local function editor(win)
  if not valid(win) or api.nvim_win_get_config(win).relative ~= '' then return false end
  local buf = api.nvim_win_get_buf(win)
  return vim.bo[buf].buftype == '' and vim.bo[buf].buflisted
end

local function palette()
  local p = S.opts.palette()
  api.nvim_set_hl(0, 'HankTablineSelected', { fg = p.crust, bg = p.green, bold = true })
  api.nvim_set_hl(0, 'HankTablineInactive', { fg = p.overlay2, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineTrack', { fg = p.overlay0, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineAccent', { fg = p.green, bg = p.base })
  api.nvim_set_hl(0, 'HankTablineProject', { fg = p.green, bg = p.base, bold = true })
end

-- Slice by screen cells, retaining composing characters and padding split wide glyphs.
local function slice(text, from, width)
  local out, col = {}, 0
  for i = 0, vim.fn.strchars(text, true) - 1 do
    local char = vim.fn.strcharpart(text, i, 1, true)
    local w = vim.fn.strdisplaywidth(char)
    if col >= from and col + w <= from + width then
      out[#out + 1] = char
    elseif col < from + width and col + w > from then
      out[#out + 1] = string.rep(' ', math.min(col + w, from + width) - math.max(col, from))
    end
    col = col + w
    if col >= from + width then break end
  end
  return table.concat(out)
end

local function collect()
  -- Use the tab's working directory, so changing buffers cannot move the label.
  local cwd = vim.fn.getcwd(-1, 0)
  local name = vim.fn.fnamemodify(cwd, ':t')
  local label = '  ' .. (name == '' and cwd or name):gsub('%c', '?')
  local limit = math.floor(vim.o.columns / 4)
  local room = math.max(0, limit - 1)
  if vim.fn.strdisplaywidth(label) > room then
    label = slice(label, 0, math.max(0, room - 1)) .. (room > 0 and '…' or '')
  end
  S.prefix = slice(label .. ' ', 0, limit)
  S.left = vim.fn.strdisplaywidth(S.prefix)
  local bufs, names, counts = {}, {}, {}
  for _, b in ipairs(api.nvim_list_bufs()) do
    if vim.bo[b].buflisted and vim.bo[b].buftype == '' then
      local path = api.nvim_buf_get_name(b)
      local name = path == '' and '[No Name]' or vim.fn.fnamemodify(path, ':t')
      bufs[#bufs + 1], names[b] = b, name
      counts[name] = (counts[name] or 0) + 1
    end
  end
  local win = S.editors[api.nvim_get_current_tabpage()]
  local active = editor(win) and api.nvim_win_get_buf(win) or bufs[1]
  S.tabs = {}
  local col, selected = 0, nil
  for _, b in ipairs(bufs) do
    local label = names[b]
    if counts[label] > 1 then
      local path = api.nvim_buf_get_name(b)
      label = path == '' and ('[No Name:' .. b .. ']') or vim.fn.fnamemodify(path, ':~:.')
    end
    label = label:gsub('%c', '?') .. (vim.bo[b].modified and ' ●' or '')
    local text = ' ' .. label .. ' '
    local width = vim.fn.strdisplaywidth(text)
    local tab = { buf = b, text = text, start = col, finish = col + width, active = b == active }
    S.tabs[#S.tabs + 1] = tab
    if tab.active then selected = tab end
    col = col + width
  end
  local width = vim.o.columns - S.left
  if selected then
    -- Match Posting's scroll-to-center behavior while keeping short lists left aligned.
    S.offset = math.max(0, math.min(math.floor((selected.start + selected.finish - width) / 2), col - width))
    S.target = { selected.start + 1 - S.offset + S.left, selected.finish - 1 - S.offset + S.left }
  else
    S.offset, S.target = 0, { 0, 0 }
  end
end

function M.render()
  local parts = { '%#HankTablineProject#%0@v:lua.HankTablineNoop@', S.prefix:gsub('%%', '%%%%'), '%X' }
  for _, tab in ipairs(S.tabs) do
    local left, right = math.max(tab.start, S.offset), math.min(tab.finish, S.offset + vim.o.columns - S.left)
    if left < right then
      local text = slice(tab.text, left - tab.start, right - left):gsub('%%', '%%%%')
      parts[#parts + 1] = ('%%#%s#%%%d@v:lua.HankTablineClick@%s%%X'):format(
        tab.active and 'HankTablineSelected' or 'HankTablineInactive', tab.buf, text)
    end
  end
  parts[#parts + 1] = '%#HankTablineInactive#%='
  return table.concat(parts)
end

function M.select(buf)
  vim.schedule(function()
    if not api.nvim_buf_is_valid(buf) or not vim.bo[buf].buflisted then return end
    local tab = api.nvim_get_current_tabpage()
    local win = S.editors[tab]
    if not editor(win) then
      for _, w in ipairs(api.nvim_tabpage_list_wins(tab)) do
        if editor(w) then win = w; break end
      end
    end
    if not editor(win) then return end
    api.nvim_set_current_win(win)
    -- :buffer retains Neovim's modified-buffer/hidden handling.
    vim.cmd.buffer(buf)
  end)
end

local function draw(start, finish)
  if not valid(S.bar) then return end
  local cells, first, last = {}, nil, nil
  start, finish = math.floor(start * 2 + 0.5) / 2, math.floor(finish * 2 + 0.5) / 2
  for col = 0, vim.o.columns - 1 do
    local char, accent = '━', false
    if col >= start and col + 1 <= finish then
      accent = true
    elseif col < start and col + 1 > start and col + 1 <= finish then
      char, accent = '╺', true
    elseif col >= start and col < finish and col + 1 > finish then
      char, accent = '╸', true
    elseif col + 1 == start then
      char = '╸'
    elseif col == finish then
      char = '╺'
    end
    if col < S.left then char, accent = '━', false end
    cells[#cells + 1] = char
    if accent then first, last = first or col, col + 1 end
  end
  vim.bo[S.buf].modifiable = true
  api.nvim_buf_set_lines(S.buf, 0, -1, false, { table.concat(cells) })
  vim.bo[S.buf].modifiable = false
  api.nvim_buf_clear_namespace(S.buf, ns, 0, -1)
  if first then
    api.nvim_buf_set_extmark(S.buf, ns, 0, first * 3, { end_col = last * 3, hl_group = 'HankTablineAccent' })
  end
  S.position = { start, finish }
end

local function animate(instant)
  local target = S.target
  if not instant and S.destination and vim.deep_equal(target, S.destination) then return end
  S.destination = vim.deepcopy(target)
  S.generation = S.generation + 1
  local generation = S.generation
  if instant or not S.position or S.opts.duration == 0 then draw(unpack(target)); return end
  local origin, begun = S.position, vim.uv.hrtime()
  local function step()
    if generation ~= S.generation or not valid(S.bar) then return end
    local t = math.min(1, (vim.uv.hrtime() - begun) / (S.opts.duration * 1e9))
    local eased = t < 0.5 and 4 * t ^ 3 or 1 - (-2 * t + 2) ^ 3 / 2
    draw(origin[1] + (target[1] - origin[1]) * eased, origin[2] + (target[2] - origin[2]) * eased)
    if t < 1 then vim.defer_fn(step, 16) end
  end
  step()
end

local function geometry()
  local current_tab = api.nvim_get_current_tabpage()
  for win in pairs(S.reserved) do
    if not valid(win) then S.reserved[win] = nil end
  end
  for tab in pairs(S.editors) do
    if not api.nvim_tabpage_is_valid(tab) then S.editors[tab] = nil end
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
    local win = api.nvim_get_current_win()
    if editor(win) then S.editors[api.nvim_get_current_tabpage()] = win end
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

function M.setup(opts)
  S.opts = vim.tbl_extend('force', { duration = 0.3, underline = false }, opts)
  local group = api.nvim_create_augroup('hank_tabline', { clear = true })
  palette()
  vim.o.showtabline = 2
  vim.o.tabline = "%!v:lua.require('hank-tabline').render()"
  _G.HankTablineClick = function(buf, _, button)
    if button == 'l' then M.select(buf) end
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
      local col = mouse.screencol - 1 - S.left + S.offset
      if mouse.screencol <= S.left then return '' end
      for _, tab in ipairs(S.tabs) do
        if col >= tab.start and col < tab.finish then M.select(tab.buf); break end
      end
      return ''
    end
    return '<LeftMouse>'
  end, { expr = true, desc = 'Select a buffer from the tab underline' })
  queue(true)
end

return M
