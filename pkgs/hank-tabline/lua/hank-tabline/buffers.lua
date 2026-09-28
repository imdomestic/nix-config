-- The buffer tabs: the one section that scrolls and fills the space between the others.
local api = vim.api

local B = { name = 'buffers', align = 'fill', editors = {} }

local function editor(win)
  if not win or not api.nvim_win_is_valid(win) or api.nvim_win_get_config(win).relative ~= '' then return false end
  local buf = api.nvim_win_get_buf(win)
  return vim.bo[buf].buftype == '' and vim.bo[buf].buflisted
end

function B.update()
  for tab in pairs(B.editors) do
    if not api.nvim_tabpage_is_valid(tab) then B.editors[tab] = nil end
  end
  local win = api.nvim_get_current_win()
  if editor(win) then B.editors[api.nvim_get_current_tabpage()] = win end
end

function B.items()
  local bufs, names, counts = {}, {}, {}
  for _, b in ipairs(api.nvim_list_bufs()) do
    if vim.bo[b].buflisted and vim.bo[b].buftype == '' then
      local path = api.nvim_buf_get_name(b)
      local name = path == '' and '[No Name]' or vim.fn.fnamemodify(path, ':t')
      bufs[#bufs + 1], names[b] = b, name
      counts[name] = (counts[name] or 0) + 1
    end
  end
  local win = B.editors[api.nvim_get_current_tabpage()]
  -- The highlight follows the last editor window, not the focused sidebar.
  local active = editor(win) and api.nvim_win_get_buf(win) or bufs[1]
  local items = {}
  for _, b in ipairs(bufs) do
    local label = names[b]
    if counts[label] > 1 then
      local path = api.nvim_buf_get_name(b)
      label = path == '' and ('[No Name:' .. b .. ']') or vim.fn.fnamemodify(path, ':~:.')
    end
    label = label:gsub('%c', '?') .. (vim.bo[b].modified and ' ●' or '')
    items[#items + 1] = { id = b, text = ' ' .. label .. ' ', active = b == active }
  end
  return items
end

function B.click(buf, button)
  if button ~= 'l' then return end
  vim.schedule(function()
    if not api.nvim_buf_is_valid(buf) or not vim.bo[buf].buflisted then return end
    local tab = api.nvim_get_current_tabpage()
    local win = B.editors[tab]
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

return B
