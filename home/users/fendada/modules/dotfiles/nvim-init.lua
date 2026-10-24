vim.g.mapleader = " "
vim.g.maplocalleader = "\\"
vim.opt.number = true
vim.opt.mouse = "a"
vim.opt.showmode = false

vim.opt.breakindent = true

-- Save undo history
vim.opt.undofile = true

-- Case-insensitive searching UNLESS \C or one or more capital letters in the search term
vim.opt.ignorecase = true
vim.opt.smartcase = true

-- Keep signcolumn on by default
vim.o.signcolumn = "yes:1"
-- vim.opt.signcolumn = "number"

-- Decrease update time
vim.opt.updatetime = 125

-- Decrease mapped sequence wait time
-- Displays which-key popup sooner
vim.opt.timeoutlen = 300

-- Configure how new splits should be opened
vim.opt.splitright = true
vim.opt.splitbelow = true

-- Sets how neovim will display certain whitespace characters in the editor.
--  See `:help 'list'`
--  and `:help 'listchars'`
-- vim.opt.list = true
-- vim.opt.listchars = { tab = '» ', trail = '·', nbsp = '␣' }

-- Preview substitutions live, as you type!
vim.opt.inccommand = "split"

-- Show which line your cursor is on
vim.opt.cursorline = true

-- Minimal number of screen lines to keep above and below the cursor.
vim.opt.scrolloff = 10

-- views can only be fully collapsed with the global statusline
vim.opt.laststatus = 3

vim.o.fillchars = "eob: "

vim.keymap.set('n', '<Esc>', '<Cmd>nohlsearch<CR>')
vim.keymap.set("n", "[b", "<Cmd>bprev<CR>")
vim.keymap.set("n", "]b", "<Cmd>bnext<CR>")
-- vim.keymap.set("n", "<leader>c", function() require('snacks').bufdelete() end)
vim.keymap.set("n", "<leader>/", "gcc", { remap = true, desc = "Toggle comment line" })
vim.keymap.set("v", "<leader>/", "gc", { remap = true, desc = "Toggle comment" })
-- vim.keymap.set("n", "<leader>lf", "<cmd>Guard fmt<CR>")

vim.keymap.set("n", "<leader>q", "<Cmd>q<CR>")
vim.keymap.set("n", "<leader>Q", "<Cmd>qa!<CR>")

vim.keymap.set("i", "jk", "<Esc>")

vim.keymap.set("v", "J", "5j")
vim.keymap.set("n", "<leader>w", "<cmd>w<CR>")
vim.keymap.set("n", "j", "gj")
vim.keymap.set("n", "k", "gk")
vim.keymap.set("x", "j", "gj")
vim.keymap.set("x", "k", "gk")

vim.keymap.set("n", ";", ":")

-- vim.keymap.set("n", "<M-n>", function()
--   require("snacks").terminal()
-- end, { desc = "Toggle terminal" })
-- vim.keymap.set("t", "<M-n>", function()
--   require("snacks").terminal()
-- end, { desc = "Toggle terminal" })
-- vim.keymap.set("n", "<leader>th", function()
--   require("snacks").terminal()
-- end, { desc = "Toggle terminal" })

-- Exit terminal mode in the builtin terminal with a shortcut that is a bit easier
-- for people to discover. Otherwise, you normally need to press <C-\><C-n>, which
-- is not what someone will guess without a bit more experience.
--
-- NOTE: This won't work in all terminal emulators/tmux/etc. Try your own mapping
-- or just use <C-\><C-n> to exit terminal mode
vim.keymap.set("t", "<Esc><Esc>", "<C-\\><C-n>", { desc = "Exit terminal mode" })

-- Keybinds to make split navigation easier.
--  Use CTRL+<hjkl> to switch between windows
--
--  See `:help wincmd` for a list of all window commands
vim.keymap.set("n", "<C-h>", "<C-w><C-h>", { desc = "Move focus to the left window" })
vim.keymap.set("n", "<C-l>", "<C-w><C-l>", { desc = "Move focus to the right window" })
vim.keymap.set("n", "<C-j>", "<C-w><C-j>", { desc = "Move focus to the lower window" })
vim.keymap.set("n", "<C-k>", "<C-w><C-k>", { desc = "Move focus to the upper window" })

vim.keymap.set("n", "<leader>ui", function()
  local input_avail, input = pcall(vim.fn.input, "Set indent value (>0 expandtab, <=0 noexpandtab): ")
  if input_avail then
    local indent = tonumber(input)
    if not indent or indent == 0 then
      return
    end
    vim.bo.expandtab = (indent > 0) -- local to buffer
    indent = math.abs(indent)
    vim.bo.tabstop = indent         -- local to buffer
    vim.bo.softtabstop = indent     -- local to buffer
    vim.bo.shiftwidth = indent      -- local to buffer
  end
end)

-- vim.cmd([[inoremap ( ()<Left>]])
-- vim.cmd([[inoremap () ()]])
--
-- vim.cmd([[inoremap ( ()<Left>]])
-- vim.cmd([[inoremap () ()]])
--
-- vim.cmd("inoremap { {}<Left>")
-- vim.cmd("inoremap {} {}")
--
-- vim.cmd("inoremap [ []<Left>")
-- vim.cmd("inoremap [] []")

vim.cmd([[set cmdheight=0]])

vim.api.nvim_create_autocmd('FileType', {
  pattern = { 'cpp', 'haskell', 'rust', 'c', 'lua' },
  callback = function() vim.treesitter.start() end,
})

-- Highlight when yanking (copying) text
vim.api.nvim_create_autocmd("TextYankPost", {
  desc = "Highlight when yanking (copying) text",
  group = vim.api.nvim_create_augroup("highlight-yank", { clear = true }),
  callback = function()
    vim.highlight.on_yank()
  end,
})

-- fix cursor in windows terminal
vim.api.nvim_create_autocmd("VimLeave", {
  pattern = "*",
  callback = function()
    vim.o.guicursor = ""
    vim.fn.chansend(vim.v.stderr, "\x1b[ q]")
  end,
})

-- Bootstrap lazy.nvim
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
---@diagnostic disable-next-line: undefined-field
if not (vim.uv or vim.loop).fs_stat(lazypath) then
  local lazyrepo = "https://github.com/folke/lazy.nvim.git"
  local out = vim.fn.system({ "git", "clone", "--filter=blob:none", "--branch=stable", lazyrepo, lazypath })
  if vim.v.shell_error ~= 0 then
    vim.api.nvim_echo({
      { "Failed to clone lazy.nvim:\n", "ErrorMsg" },
      { out,                            "WarningMsg" },
      { "\nPress any key to exit..." },
    }, true, {})
    vim.fn.getchar()
    os.exit(1)
  end
end
vim.opt.rtp:prepend(lazypath)

require("lazy").setup({
  spec = {
    { import = 'plugins' },
  },
  ui = {
    backdrop = 70,
    border = "rounded",
  },
})
