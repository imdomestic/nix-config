-- Optional fixed label: folder icon and the tabpage's working directory name.
local slice = require('hank-tabline.slice')

return {
  name = 'project',
  align = 'left',
  style = 'label',
  items = function(ctx)
    -- The tab's working directory, so changing buffers cannot move the label.
    local cwd = vim.fn.getcwd(-1, 0)
    local name = vim.fn.fnamemodify(cwd, ':t')
    local label = ' ' .. vim.fn.nr2char(0xf07b) .. ' ' .. (name == '' and cwd or name):gsub('%c', '?')
    -- Inside a sidebar block the label gets whatever the icons leave over.
    local limit = ctx.width or math.floor(ctx.columns / 4)
    local room = math.max(0, limit - 1)
    if vim.fn.strdisplaywidth(label) > room then
      label = slice(label, 0, math.max(0, room - 1)) .. (room > 0 and '…' or '')
    end
    return { { id = 'project', text = slice(label .. ' ', 0, limit) } }
  end,
}
