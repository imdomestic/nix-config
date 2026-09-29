-- Panel specs for plugins that already own their windows. Each takes the display
-- fields (id, icon, icon_inactive, side) and fills in open/close/is_open.
local A = {}
local api = vim.api

local function windows(predicate)
  local found = {}
  for _, win in ipairs(api.nvim_tabpage_list_wins(0)) do
    if api.nvim_win_get_config(win).relative == '' and predicate(api.nvim_win_get_buf(win)) then
      found[#found + 1] = win
    end
  end
  return found
end

local function filetype(ft)
  return function(buf) return vim.bo[buf].filetype == ft end
end

-- A plugin that opens a split of a known filetype (aerial, dbui, ...).
function A.window(spec)
  local match = filetype(assert(spec.ft, 'hank-panels: window adapter needs ft'))
  spec.is_open = function() return #windows(match) > 0 end
  spec.owns = function(win) return match(api.nvim_win_get_buf(win)) end
  spec.close = spec.close or function()
    for _, win in ipairs(windows(match)) do api.nvim_win_close(win, false) end
  end
  return spec
end

-- A Snacks picker shown as a sidebar (the explorer, git_status, ...).
function A.snacks(spec)
  local source = spec.source or spec.id
  local function active()
    local snacks = package.loaded['snacks']
    return snacks and snacks.picker.get({ source = source }) or {}
  end
  spec.is_open = function() return #active() > 0 end
  -- The list and input are floats over the root split; any of them counts.
  spec.owns = function(win)
    for _, picker in ipairs(active()) do
      if picker.layout.root and picker.layout.root.win == win then return true end
      for _, w in pairs(picker.layout.wins or {}) do
        if w.win == win then return true end
      end
    end
    return false
  end
  spec.open = function() require('snacks').picker.pick(source, vim.deepcopy(spec.opts or {})) end
  spec.close = function()
    for _, picker in ipairs(active()) do picker:close() end
  end
  return spec
end

-- Snacks gives every picker the same highlight groups, so a picker shown as a panel
-- (a split) gets its own `winhl` mapping, e.g. `{ NormalFloat = 'MyPanel' }`. Call it
-- from the picker's on_show. Layout passes rebuild child window options from
-- `layout.win_opts`, so the mapping goes there as well. The split also takes the
-- global 'fillchars' (vim.go: vim.o would read Snacks' own window-local value), which
-- would otherwise bring the separator line back.
function A.snacks_surface(picker, winhl)
  local layout = picker.layout
  if not (layout and layout.split) then return end
  local function patch(opts)
    opts.wo = opts.wo or {}
    opts.wo.winhighlight = Snacks.util.winhl(opts.wo.winhighlight or '', winhl)
  end
  patch(layout.root.opts)
  layout.root.opts.wo.fillchars = vim.go.fillchars
  for name, win in pairs(layout.wins or {}) do
    patch(win.opts)
    if layout.win_opts and layout.win_opts[name] then patch(layout.win_opts[name]) end
  end
  for _, win in ipairs(vim.list_extend({ layout.root }, vim.tbl_values(layout.wins or {}))) do
    if win:win_valid() then Snacks.util.wo(win.win, { winhighlight = win.opts.wo.winhighlight }) end
  end
  if layout.root:win_valid() then vim.wo[layout.root.win].fillchars = vim.go.fillchars end
end

-- A Snacks terminal in a split. Closing hides it, so the shell keeps running and
-- comes back on the next open.
function A.snacks_terminal(spec)
  local match = filetype('snacks_terminal')
  spec.side = spec.side or 'bottom'
  spec.is_open = function() return #windows(match) > 0 end
  spec.owns = function(win) return match(api.nvim_win_get_buf(win)) end
  spec.open = function() require('snacks').terminal.toggle(spec.cmd, vim.deepcopy(spec.opts)) end
  spec.close = function()
    local tab = api.nvim_get_current_tabpage()
    for _, terminal in ipairs(require('snacks').terminal.list()) do
      if terminal:win_valid() and api.nvim_win_get_tabpage(terminal.win) == tab then terminal:hide() end
    end
  end
  return spec
end

-- lean.nvim keeps one infoview per tabpage and opens it with `botright vsplit`.
function A.lean_infoview(spec)
  local lean = filetype('lean')
  local info = filetype('leaninfo')
  spec.side = spec.side or 'right'
  local function window()
    local infoview = package.loaded['lean.infoview']
    local current = infoview and infoview.get_current_infoview()
    return current and current.window
  end
  spec.is_open = function() return window() ~= nil end
  spec.owns = function(win)
    local current = window()
    return current ~= nil and current.id == win
  end
  -- lean.nvim is lazy-loaded on the lean filetype; offer the panel only around Lean.
  spec.available = function()
    return package.loaded['lean.infoview'] ~= nil
      and (#windows(lean) > 0 or #windows(info) > 0)
  end
  spec.open = function() require('lean.infoview').open() end
  spec.close = function() require('lean.infoview').close() end
  return spec
end

return A
