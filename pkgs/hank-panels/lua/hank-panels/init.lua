-- Registry of sidebar panels (explorer, git, outline, lean infoview, ...): one open
-- panel per side, toggled by id. Placement stays with each plugin's own settings.
local M = {}
local api = vim.api
local P = { list = {}, by_id = {} }

local function glyph(icon)
  return type(icon) == 'number' and vim.fn.nr2char(icon) or icon
end

local function call(panel, name)
  local ok, result = pcall(panel[name])
  if not ok then
    vim.notify(('hank-panels: %s.%s: %s'):format(panel.id, name, result), vim.log.levels.ERROR)
    return nil
  end
  return result
end

local function is_open(panel)
  local ok, open = pcall(panel.is_open)
  return ok and open == true
end

local function available(panel)
  if not panel.available then return true end
  local ok, yes = pcall(panel.available)
  return ok and yes == true
end

-- Panels attach to whatever buffer is current (aerial, the lean infoview), so open
-- them from an ordinary file window rather than from another sidebar.
local function focus_editor()
  local function editor(win)
    if not win or win == 0 or not api.nvim_win_is_valid(win) or api.nvim_win_get_config(win).relative ~= '' then
      return false
    end
    return vim.bo[api.nvim_win_get_buf(win)].buftype == ''
  end
  if editor(api.nvim_get_current_win()) then return end
  local previous = vim.fn.win_getid(vim.fn.winnr('#'))
  if editor(previous) then api.nvim_set_current_win(previous); return end
  for _, win in ipairs(api.nvim_tabpage_list_wins(0)) do
    if editor(win) then api.nvim_set_current_win(win); return end
  end
end

function M.setup(opts)
  P.list, P.by_id = {}, {}
  for _, panel in ipairs((opts or {}).panels or {}) do
    assert(panel.id and panel.icon and panel.open and panel.close and panel.is_open,
      'hank-panels: a panel needs id, icon, open, close and is_open')
    panel.side = panel.side or 'left'
    P.list[#P.list + 1] = panel
    P.by_id[panel.id] = panel
  end
end

function M.get(id)
  return P.by_id[id]
end

function M.is_open(id)
  local panel = P.by_id[id]
  return panel ~= nil and is_open(panel)
end

function M.open(id)
  local panel = assert(P.by_id[id], 'hank-panels: unknown panel ' .. tostring(id))
  if is_open(panel) then return end
  for _, other in ipairs(P.list) do
    if other ~= panel and other.side == panel.side and is_open(other) then call(other, 'close') end
  end
  focus_editor()
  call(panel, 'open')
end

function M.close(id)
  local panel = assert(P.by_id[id], 'hank-panels: unknown panel ' .. tostring(id))
  if is_open(panel) then call(panel, 'close') end
end

function M.toggle(id)
  if M.is_open(id) then M.close(id) else M.open(id) end
end

-- A hank-tabline section: one icon per available panel on `side`, filled when open.
function M.section(side)
  return {
    name = 'panels-' .. side,
    style = 'icon',
    -- Light the rail under the glyph only, with half-cell gaps either side.
    pad = 0.5,
    items = function()
      local items = {}
      for _, panel in ipairs(P.list) do
        if panel.side == side and available(panel) then
          local open = is_open(panel)
          local icon = glyph(open and panel.icon or (panel.icon_inactive or panel.icon))
          items[#items + 1] = { id = panel.id, text = ' ' .. icon .. ' ', active = open }
        end
      end
      return items
    end,
    click = function(id, button)
      if button == 'l' then vim.schedule(function() M.toggle(id) end) end
    end,
  }
end

return M
